# KakaoTalk PC 26.8.2 로컬 DB(.edb) 암호화 분석

KakaoTalk PC **26.8.2.5324** 가 로컬에 저장하는 `.edb`(SQLCipher) 데이터베이스의 암호화 방식을
리버스 엔지니어링하고, 키 복구 → 복호화까지 **end-to-end로 검증**한 기록이다.

> **범위/권한:** 분석자 본인 PC·본인 계정 데이터에 한정한 로컬 보안 연구. 배포/우회 목적이 아니며
> 실제 키·비밀값·복호화된 사용자 데이터는 리포에 **커밋하지 않는다**(`.gitignore` 참조).

---

## 1. 결론 (TL;DR)

- 암호화 라이브러리: **SQLCipher 4.6.1 community** (SQLite 3.46.1, OpenSSL 3.4.1), 페이지 4096.
- 파일 포맷: **표준 SQLCipher 4** — 앞 16B가 평문 salt, 페이지당 reserve 80B(IV 16 + HMAC 64),
  AES-256-CBC + HMAC-SHA512.
- 키 스킴: **DB마다 다른 32바이트 raw key**. KakaoTalk은 패스프레이즈가 아니라
  `PRAGMA key = "x'<64 hex>'"`(raw key)로 각 `.edb`를 연다.
- 키 유도(KDF)는 런타임 "키 매니저" 싱글턴의 비밀(`mss.dat` 유래, 재시작 불변)과 DB별 32B salt로
  이뤄지지만, **KDF 본체는 Themida VM으로 가상화**되어 알고리즘 복원은 불가.
- **복호화는 KDF 재현 없이 완료**: SQLCipher가 열린 DB마다 메모리에 남기는 **keyspec 문자열
  `x'<64hex 키><32hex 솔트>'`** 를 외부에서 읽어(디버거 불필요) 각 DB의 raw key를 그대로 획득.

### 검증 결과
- 실행 중 프로세스에서 keyspec 다수 포착 → 디스크 `.edb`와 salt로 매칭된 DB가 **전부 page‑1 복호화
  헤더 검증 통과**.
- `emoticon.edb`(234페이지)를 **전체 복호화**해 표준 SQLite로 열림: `PRAGMA integrity_check = ok`,
  `sqlite_master`에 실제 스키마 21개(`EmoticonTitle`, `KeyboardItems`, `UserData`,
  `SuggestionDictionary` 등). → **복호화 확정.**

---

## 2. 재현 방법

필요: Windows, Python 3 + `pycryptodome` (`pip install pycryptodome`). 디버거/`sqlcipher` 빌드 불필요.

```powershell
# 0) KakaoTalk을 정상 실행(디버거 없이)해 로그인·DB 오픈까지 둔다.
#    (특정 대화방 키가 필요하면 그 채팅방을 열어 둔다 — 열려 있는 DB만 포착됨)

# 1) 실행 중 프로세스에서 per-DB 키 복구 + 검증
py -I tools\kakao_keyspec_scan.py <PID> "<...\AppData\Local\Kakao\KakaoTalk\users\<hash>>" --save keys.txt

# 2) 특정 .edb를 표준 SQLite로 복호화 (스키마/무결성까지 출력)
py -I tools\kakao_edb_decrypt.py "<...\users\<hash>\emoticon.edb>" <64hex-key> out.sqlite

# (선택) 키 1건을 .edb에 대해 단독 검증
py -I tools\kakao_edb_verify.py "<...\some.edb>" "x'<64hex>'"
```

`<PID>`는 실행 중 `KakaoTalk.exe`의 PID. 스캔은 `OpenProcess(VM_READ)`로 메모리만 읽으므로 **프로세스에
attach하지 않고**, 따라서 Themida anti-debug를 **트리거하지 않는다**.

---

## 3. 도구 (`tools/`)

| 파일 | 역할 |
|---|---|
| `kakao_keyspec_scan.py` | 실행 중 프로세스 메모리에서 SQLCipher keyspec 스캔 → `.edb` salt 매칭 → page‑1 검증. **핵심 도구** |
| `kakao_edb_decrypt.py` | `.edb` + 32B 키 → 표준 `.sqlite` 복호화, `integrity_check`/스키마 출력 |
| `kakao_edb_verify.py` | 키 1건을 `.edb` page‑1(AES 헤더 + HMAC 교차검증)로 검증 |
| `peoff.py`, `rea_pc.py` | 초기 PE/오프셋 보조 스크립트 |

모든 도구는 **비밀값 미포함**. 키/복호화 산출물(`*.sqlite`, `keys.txt`, `*.keys`)은 `.gitignore`로 제외.

---

## 4. 문서 (`docs/`, `re/`)

| 문서 | 내용 |
|---|---|
| `docs/01_db_encryption_26.8.2.md` | 1차 결론(라이브러리/포맷/salt) + 전체 진행 상황 체크리스트 |
| `docs/02_key_derivation_static.md` | 정적 분석: 키 조립/KDF 함수 식별(덤프 기준). 동적 결과로 갱신·정정됨 |
| `docs/03_keystore_and_open_path.md` | 평상시 DB 오픈 경로 + 키 저장소 파일 후보(`mss.dat` 등) |
| `docs/04_runtime_keystore_dynamic.md` | **동적 분석 본편**: 키 매니저 싱글턴 구조, KDF 호출 체인, 라이브 디버깅 시도(Plan A/B), **§8 최종 keyspec 스캔 방법·검증 결과** |
| `re/pseudo/sub_141CCAC20_key_assembly.md` | 키 조립 함수 주석 디스어셈블 + Themida VM 진입 지점 |
| `re/pseudo/sub_141C03D90_migrate_one.c` | 레거시→SQLCipher 마이그레이션 함수 의사코드 |

---

## 5. 조사 이력 (어떤 길을 거쳤나)

1. **정적 분석** (`docs/01`,`02`,`03`): 덤프 `KakaoTalk_dump_SCY.exe`에서 SQLCipher/OpenSSL 문자열,
   `ATTACH ... KEY ?`, 마이그레이션 로그 등으로 **raw-key 스킴**과 키 조립 함수(`sub_141CCAC20`),
   KDF 함수(`sub_141CCB9A0`)를 식별. 단 KDF의 정확한 알고리즘·ikm 출처는 미확정.
2. **동적 분석** (`docs/04`): 실행 중 프로세스에서 키 매니저 싱글턴(`*(void**)0x142E42068`) 구조를
   확정 — DB별 32B salt 맵, inline 시크릿, `"v2:"` 라벨, KDF 호출 체인. `sub_141CCAC20`을 완전히
   해독해 **최종 키 = `"x'" + hex(out2) + "'"`** 임을 밝힘.
3. **벽 2개 확인**:
   - 정적: 코어 KDF `sub_141CCB9A0`이 **Themida VM(0x144…)으로 점프** → 알고리즘 복원 불가.
   - 동적: x64dbg 콜드 로드가 **Themida anti-debug로 정지**(직접 syscall로 유저모드 ScyllaHide 우회).
4. **라이브 포착 시도 (Plan A vs B)** — `docs/04` §6:
   - **Plan A**: 이미 Themida를 통과한 보호 세션을 재사용해 BP로 **관찰만**. 재현 보장이 없어 미선택.
   - **Plan B**: x64dbg로 EP부터 로드해 OEP까지 끌고 가며 ScyllaHide로 돌파 후 BP. **수행했으나
     anti-debug로 차단**(BP 유무와 무관하게 정지).
5. **돌파구 — keyspec 메모리 스캔** (`docs/04` §8): 디버거를 아예 쓰지 않고, SQLCipher가 열린 DB마다
   codec에 보관하는 keyspec `x'<키><솔트>'`를 `ReadProcessMemory`로 읽어 키를 직접 획득 → **복호화 검증 완료.**

---

## 6. 한계 / 다음 단계

- 스캔 시점에 **열려 있는 DB만** 키가 메모리에 상주한다. `chatLogs_*.edb`(대화 내용)는 해당 채팅방을
  연 뒤 스캔해야 포착된다.
- 최신 데이터 상당수는 체크포인트 전이라 **`<edb>-wal`** 에 있다. WAL도 동일한 per-page 암호 스킴이므로
  별도 복호화 지원을 추가할 수 있다(예정).
- page‑1 HMAC-SHA512 교차검증은 기본 파라미터 스윕에서 불일치(키 문제 아님 — KakaoTalk이 HMAC 유도
  파라미터를 커스터마이즈한 것으로 보임). 복호화 자체는 b‑tree `integrity_check=ok`로 독립 확인됨.

---

## 환경

- 대상: `C:\Program Files\Kakao\KakaoTalk\KakaoTalk.exe` (FileVersion 26.8.2.5324), Themida 보호.
- 데이터: `%LOCALAPPDATA%\Kakao\KakaoTalk\users\<userhash>\...`
- 분석 도구: x64dbg(+ScyllaHide), IDA(`.i64`), capstone, Python(pycryptodome), 외부 ReadProcessMemory.
