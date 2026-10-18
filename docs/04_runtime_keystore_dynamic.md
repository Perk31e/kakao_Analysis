# KakaoTalk PC 26.8.2 — 런타임 키 저장소 구조 (동적 분석, x64dbg)

분석일: 2026-10-18~19 / 대상: 실행 중 `KakaoTalk.exe`(PID 11912 세션), 이미지 base `0x140000000`
도구: x64dbg(ScyllaHide 세션) + 덤프 `KakaoTalk_dump_SCY.exe` 정적 대조.
주의: 아래 **주소 중 힙/컨텍스트 주소(0x04xxxxxx, 0x05xxxxxx)는 세션마다 바뀐다.** 바이트 값(시크릿/솔트)은
키 저장소(`mss.dat`)에서 유도되므로 재시작해도 동일할 것으로 보인다(미검증).

## 1. 핵심 결론 — DB별 raw key는 메모리의 "키 매니저" 싱글턴에서 나온다

```
sub_141BA8180()  ──►  *(void**)0x142E42068  = ctx (키 매니저 싱글턴)
                                     │
                                     ├─ ctx+0x08  : 데이터 base 경로(wstring) = ...\users\<hash>
                                     ├─ ctx+0x68  : SECRET_A (32B, 고엔트로피, inline)
                                     ├─ ctx+0xE0  : KDF 입력 문자열/버퍼 핸들(힙 포인터) ★KDF가 읽음
                                     ├─ ctx+0x100 : std::string "v2:" (KDF 라벨/버전)
                                     ├─ ctx+0x120 : 32B 고엔트로피 블록(inline)
                                     └─ ctx+0x148/+0x158/+0x170 : DB별 키맵(unordered_map)
```

- `sub_141CCAC20(ctx, &out, &dbPath)` 가 **DB마다** `x'<64 hex>'` raw key 문자열을 만들어 돌려준다(MSVC
  `std::string` 반환, rax=버퍼). 즉 §02의 정적 추정(raw-key 스킴)이 런타임으로 확인됨.
- 입력 `dbPath`(a3=r8)는 `sub_141CC8B40`에서 **`std::filesystem::relative(path, base)`** 로 정규화되어
  `chat_data\chatLogs_<id>.edb` 같은 **base 상대경로**가 되고, 이 문자열이 맵의 키다.

## 2. DB별 키 맵 (unordered_map<상대경로, 노드>)

- 버킷 배열 `ctx+0x158`, 마스크 `ctx+0x170`(=0x3F → 64버킷), 리스트 센티넬 `ctx+0x148`.
- 키 해시 = **FNV-1a 64비트** (`off=0xCBF29CE484222325`, `prime=0x100000001B3`) over 정규화 상대경로.
- 노드 레이아웃:
  | off | 내용 |
  |---|---|
  | +0x00 | `_Next` |
  | +0x08 | `_Prev` |
  | +0x10 | key `std::string` (상대경로, 예 `chat_data\chatLogs_366589969555943.edb`) |
  | +0x30 | **DB별 32바이트 솔트** (KDF 입력; SQLCipher 파일 헤더 솔트와는 **다름**) |

- 즉 각 .edb는 자기 노드의 32B 솔트를 가지며, raw key = `KDF(ctx 시크릿들, 노드 솔트)`.

## 3. 키 조립/KDF 호출 체인 (sub_141CCAC20 내부, 노드 발견 후)

```
esi  = (*(ctx+0xD8))->vcall[+0x10]()                    // int (kdf_iter/모드 후보)
rax1 = sub_141CCC710(ctx, &tmp, ctx+0x68)               // SECRET_A 로 KDF 입력 구성
rax2 = sub_141CCB9A0(&out1, &loc, r8=rax1, r9=ctx+0xE0) // 코어 KDF (정적: "sha256" 파라미터)
rax3 = sub_141CCBF30(&out2, rdx=node+0x30(salt), r8=rax2, r9=ctx+0xE0)  // 솔트 결합
       → out1/out2 를 ASCII hex 로 포매팅해 out = "x'<64hex>'"
```

- KDF가 실제로 읽는 입력: **`ctx+0x68`(SECRET_A)**, **`ctx+0xE0`(힙 포인터가 가리키는 버퍼)**,
  **`node+0x30`(DB별 솔트)**, 라벨 `"v2:"`.
- `sub_142374224` : 함수 선두의 재진입 가능 **SRW 락**(객체 `ctx+0x00`=0x04C3AEB0; +0x10 lock, +0x48 owner, +0x4C count) — 키맵의 thread-safe 초기화/보호용.

## 4. 포착한 값 (PID 11912 세션)

> ⚠️ 실제 바이트 값(SECRET_A, ctx+0x120, 노드 솔트 등)은 **이 설치본의 라이브 DB 키 재료**라 리포에 커밋하지
> 않는다. 로컬 스크래치패드 노트(`captured.md`)에만 보관. 아래는 구조/위치/관찰 결과만 기록.

- `ctx+0x68` SECRET_A: 32B 고엔트로피(inline) — 포착됨.
- `ctx+0x120`: 32B 고엔트로피(inline) — 포착됨.
- 라벨 `ctx+0x100`: std::string `"v2:"`.
- 노드 `chat_data\chatLogs_366589969555943.edb` 의 `node+0x30`: DB별 32B 솔트 — 포착됨.
- 같은 .edb 파일 헤더 솔트(첫 16B): 파일에서 바로 읽힘(비밀 아님).
  → **노드 솔트 ≠ 파일 솔트** 확인. 파일 솔트는 SQLCipher가 HMAC 키 유도에만 사용.

## 5. 오프라인 복호화 검증 (진행/미완)

- 검증 오라클(`tools/kakao_edb_verify.py`): 후보 raw key로 page1을 AES-256-CBC 복호 →
  SQLite 헤더(`page_size=0x1000`, `reserved=0x50`, 고정 `40 20 20`) 확인 + page1 HMAC-SHA512 교차검증.
  SQLCipher4 기본값(raw key면 메인키=그 32B, HMAC키=`PBKDF2-HMAC-SHA512(key, saltᵢ⊕0x3a, 2)`).
- 위 SECRET_A/B·노드솔트·라벨의 단순 조합(HKDF/HMAC/SHA256/PBKDF2, 322종)은 **불일치**.
  → KDF가 **`ctx+0xE0`가 가리키는 (아직 미포착) 버퍼**를 입력으로 쓰기 때문으로 판단(§3).
  이 세션이 종료되어 해당 버퍼 내용을 못 떠서 **오프라인 재현은 아직 미완.**

## 6. 다음 단계 (확정적 완료 경로)

가장 확실한 길은 **최종 raw key를 라이브로 1회 포착**하는 것(ikm/KDF 세부 불필요):
1. ScyllaHide 적용된 x64dbg 세션에서 `sub_141CCAC20`(0x141CCAC20) 진입 BP.
2. KakaoTalk에서 아직 안 연 채팅방을 열어 해당 `chatLogs_*.edb` 오픈을 유발 → BP 히트.
3. 진입 시 `rdx`(out `std::string` 포인터) 저장 → `StepOut` → `[rdx]` 읽으면 `x'<64hex>'`.
4. 그 키로 `tools/kakao_edb_verify.py` 실행 → page1 검증 통과하면 복호화 확정.
   (보조: `ctx+0xE0` 포인터가 가리키는 버퍼도 함께 덤프하면 §3 KDF 오프라인 재현 가능.)

> 주의: 함수 중간에서 rip을 되돌리는 in-process 호출은 선두 SRW 락 미해제 + 스택 쿠키(`__fastfail`)로
> 프로세스가 죽는다. **관찰(BP+읽기)만** 할 것.
