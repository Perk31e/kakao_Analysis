# KakaoTalk PC 26.8.2 — 런타임 키 저장소 구조 (동적 분석, x64dbg)

분석일: 2026-10-18~19 / 대상: 실행 중 `KakaoTalk.exe`, 이미지 base `0x140000000`
도구: x64dbg(ScyllaHide 세션) + 덤프 `KakaoTalk_dump_SCY.exe` 정적 대조 + 외부 ReadProcessMemory.
주의: 아래 **주소 중 힙/컨텍스트 주소(0x04xxxxxx, 0x05xxxxxx)는 세션마다 바뀐다.** 바이트 값(시크릿/솔트)은
키 저장소(`mss.dat`)에서 유도되므로 재시작해도 동일하다(검증됨: §8에서 재시작 세션의 SECRET_A/노드솔트가 이전 세션과 일치).

> ✅ **복호화 검증 완료(§8).** 최종 방법은 라이브 BP 포착이 아니라 **외부 메모리에서 SQLCipher
> keyspec 스캔**이다(디버거 불필요). KDF 코어는 Themida VM으로 가상화돼 정적 복원 불가(§3),
> 라이브 디버깅은 Themida anti-debug로 차단(§6)됐기 때문. 재사용 도구: `tools/kakao_keyspec_scan.py`,
> `tools/kakao_edb_decrypt.py`.

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

- KDF가 실제로 읽는 입력: **`ctx+0x68`(SECRET_A)**, **`node+0x30`(DB별 솔트)**, 라벨 `"v2:"`,
  반복횟수 `esi`(`(*(ctx+0xD8))->vtbl[0x10]()` 반환값).
- **`ctx+0xE0`는 키 재료가 아니다.** r9=`ctx+0xE0`로 CCB9A0/CCBF30에 전달되지만, 가리키는 힙에
  "www.digicert.com" 등 TLS/인증서 흔적이 섞여 있어 **OpenSSL 라이브러리/프로바이더 컨텍스트 핸들**로
  판단됨(데이터 아님). 이전 오프라인 재현(§5)이 이걸 데이터로 착각해 실패했던 원인.
- **코어 KDF `sub_141CCB9A0`은 셋업 후 `jmp 0x14444f323`로 Themida VM(0x144xxxxxx)에 진입** →
  알고리즘(HKDF/HMAC/PBKDF2 중 무엇인지) **정적 복원 불가**. 그래서 KDF 재현이 아니라 결과(keyspec)를
  직접 포착하는 §8 방식으로 전환.
- `sub_142374224` : 함수 선두의 재진입 가능 **SRW 락**(객체 `ctx+0x00`; +0x10 lock, +0x48 owner, +0x4C count) — 키맵의 thread-safe 초기화/보호용.

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
  → 처음엔 `ctx+0xE0` 버퍼 미포착 탓으로 봤으나, 실제로는 **(a) `ctx+0xE0`가 데이터가 아니라 OpenSSL
  컨텍스트 핸들**이고 **(b) 코어 KDF가 Themida VM으로 가상화**되어 조합을 알 수 없기 때문(§3).
  → **KDF 오프라인 재현은 폐기.** 대신 §8의 keyspec 스캔으로 결과 키를 직접 얻어 복호화를 확정함.

## 6. 라이브 BP 포착 — 시도했으나 Themida anti-debug로 차단됨 (폐기)

> ⛔ **이 경로는 실패.** 2026-10-19 재시도 결과: x64dbg로 `KakaoTalk.exe`를 OEP까지 끌고 가려
> ScyllaHide(프로파일 "Themida x86/x64", 모든 PEB/NtQuery* 훅 + NtGetContextThread/NtSetContextThread
> 추가)를 적용했으나, fresh-load 시 프로세스가 "Themida" 스플래시에서 **CPU 고정·완전 정지**하고
> x64dbg가 **브레이크인조차 못 함**. BP를 전혀 안 걸어도 동일 → 원인은 BP가 아니라 Themida의
> anti-debug(최신 Themida는 **직접 syscall**로 ntdll 훅을 우회하므로 유저모드 ScyllaHide로는 돌파 불가).
> 커널 드라이버(TitanHide 등) 없이는 라이브 디버깅 불가로 판단. → **§8 외부 메모리 방식으로 완료.**

(참고) 원래 계획했던 라이브 포착 레시피 — 커널 anti-anti-debug가 갖춰진 환경에서만 유효:
1. ScyllaHide 적용된 x64dbg 세션에서 `sub_141CCAC20`(0x141CCAC20) 진입 BP.
2. KakaoTalk에서 아직 안 연 채팅방을 열어 해당 `chatLogs_*.edb` 오픈을 유발 → BP 히트.
3. 진입 시 `rdx`(out `std::string` 포인터) 저장 → `StepOut` → `[rdx]` 읽으면 `x'<64hex>'`.
4. 그 키로 `tools/kakao_edb_verify.py` 실행 → page1 검증 통과하면 복호화 확정.
   (보조: `ctx+0xE0` 포인터가 가리키는 버퍼도 함께 덤프하면 §3 KDF 오프라인 재현 가능.)

> 주의: 함수 중간에서 rip을 되돌리는 in-process 호출은 선두 SRW 락 미해제 + 스택 쿠키(`__fastfail`)로
> 프로세스가 죽는다. **관찰(BP+읽기)만** 할 것.

## 7. 도구 메모

- **REA/Ghidra 백엔드는 이 88MB 덤프에서 전부 타임아웃**(string search, batch_decompile 모두
  `provider_timeout`). 정적 디컴파일은 기존 **IDA `.i64`**(`KakaoTalk_dump_SCY.exe.i64`)를 쓸 것.
- `sub_141CCB9A0`의 정확한 알고리즘은 **Themida VM 가상화로 정적 복원 불가**(§3). 복호화 확정에는
  불필요(§8이 결과 키를 직접 포착).

## 8. ✅ 완료 — 외부 메모리 keyspec 스캔으로 복호화 검증 (디버거 불필요)

분석일 2026-10-19. 정적(Themida VM)·동적(anti-debug) 양쪽이 막히자, **SQLCipher가 열린 각 DB의
codec에 보관하는 keyspec 문자열**을 외부에서 읽는 방식으로 전환 → 성공.

### 8.1 핵심 아이디어
- SQLCipher는 `PRAGMA key`로 연 DB마다 codec에 ASCII keyspec `x'<64hex 키><32hex 솔트>'`를 보관한다
  (ATTACH/`sqlcipher_export`용). 이 문자열은 **일반 커밋 힙**에 DB가 열려 있는 동안 상주한다.
- 따라서 **디버거 attach 없이** 다른 프로세스에서 `OpenProcess(VM_READ)` + `VirtualQueryEx` +
  `ReadProcessMemory`로 읽을 수 있다 → **Themida anti-debug가 전혀 트리거되지 않음**.
- keyspec의 32hex 솔트 = 해당 `.edb` 파일 **첫 16바이트(SQLCipher4 kdf_salt)** → 파일과 1:1 매칭 가능.

### 8.2 절차 (재현)
1. KakaoTalk을 **정상 실행**(디버거 없이)해 자동 로그인·DB 오픈까지 둔다.
2. `py -I tools/kakao_keyspec_scan.py <pid> <users_dir> --save keys.txt`
   - 읽기 전용 메모리 전 구간에서 `x'[0-9a-f]{64}[0-9a-f]{32}'` 패턴 수집.
   - 각 솔트를 `.edb` 첫 16B와 매칭, page1을 AES-256-CBC 복호해 SQLite 헤더 검증.
3. `py -I tools/kakao_edb_decrypt.py <edb> <64hex키> out.sqlite` → 표준 SQLite로 열림.

### 8.3 결과 (검증됨)
- 실행 중 프로세스 메모리에서 **keyspec 30건**(= 열려 있던 DB) 포착, 디스크 `.edb` 55개 중 **27개 매칭**.
- 매칭된 **27개 전부 page‑1 AES 복호 → 유효한 SQLCipher4 헤더**(`10 00 02 02 50 40 20 20`:
  page_size=4096, reserved=80, 고정 `40 20 20`). 오탐 확률 사실상 0 → **키 정확.**
- `emoticon.edb`(234페이지) 전체 복호화 → **`PRAGMA integrity_check = ok`**, `sqlite_master`에
  실제 스키마 **21개**(`EmoticonTitle`, `FavoriteEmoticonItems`, `KeyboardItems`, `RecentlyUsedItems`,
  `UserData`, `SuggestionDictionary` 등 테이블 + 인덱스 + 트리거) 확인. → **end-to-end 복호화 확정.**
- 재시작 세션에서도 `ctx+0x68` SECRET_A와 노드 솔트가 §4 이전 세션과 **동일** → 키 재료는 `mss.dat`
  유래로 재시작 불변임이 확인됨.

### 8.4 한계·메모
- **스캔 시점에 열려 있는 DB만** 포착된다. `chatLogs_*.edb`는 해당 채팅방을 열어야 codec이 상주 →
  대화 DB 키를 원하면 그 방들을 연 뒤 스캔. (이번엔 메타데이터 계열 27개가 열려 있었음)
- 최신 데이터 상당수는 체크포인트 전이라 **`<edb>-wal`** 에 있음(동일 per-page 스킴으로 별도 복호 가능).
- page‑1 HMAC-SHA512 교차검증은 기본 파라미터(`fast_kdf_iter=2`, salt⊕0x3a) 스윕으로 **불일치** —
  KakaoTalk이 HMAC 유도 파라미터를 커스터마이즈한 것으로 보임(키 문제 아님). 복호화 자체는 234페이지
  b‑tree 구조가 `integrity_check=ok`로 완전 정상이라 **바이트 단위로 정확**함이 독립 확인됨.
- 실제 키/비밀 바이트는 민감정보라 리포에 **커밋하지 않음**(로컬 `keys.txt`·스크래치패드에만).
