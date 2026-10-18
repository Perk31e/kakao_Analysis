# KakaoTalk PC 26.8.2.5324 로컬 DB(.edb) 암호화 분석 — 1차 결과

분석일: 2026-10-18 / 대상: `C:\Program Files\Kakao\KakaoTalk\KakaoTalk.exe` (FileVersion 26.8.2.5324)
데이터 경로: `%LOCALAPPDATA%\Kakao\KakaoTalk\users\<userhash>\...`

## 1. 결론 요약

| 항목 | 결과 | 근거 |
|---|---|---|
| 암호화 라이브러리 | **SQLCipher 4.6.1 community** | 덤프 내 문자열 `community` / `4.6.1` (0x26d2ee0) |
| SQLite 베이스 | 3.46.1 (2024-08-13 09:16:08 c9c2ab54…) | 소스 ID 문자열 |
| 암호 provider | OpenSSL 3.4.1 (11 Feb 2025) | `OpenSSL 3.4.1 11 Feb 2025` |
| 페이지 크기 | 4096 | WAL 헤더 page size = 0x1000, .edb 크기 모두 4096 배수 |
| 페이지 1 헤더 | 평문 `SQLite format 3` 없음, 첫 16바이트 = salt | 전 파일 헤더 무작위 |
| salt 고정성 | DB별로 고정 | `TalkUserDB.edb` 첫 16B == WAL 첫 프레임 페이지 첫 16B |
| WAL | 헤더/프레임 헤더 평문, 페이지 본문만 암호화 | WAL magic 0x377f0682 평문 확인 (SQLCipher 표준 동작) |

→ 파일 포맷은 **표준 SQLCipher 4** 레이아웃과 일치한다. SQLCipher 4 기본값이라면:
AES-256-CBC, PBKDF2-HMAC-SHA512 256,000회, HMAC-SHA512, reserve 80B(IV 16 + HMAC 64), page 4096, plaintext header 0.
(KakaoTalk이 `PRAGMA kdf_iter`/`cipher_*`로 기본값을 바꾸는지, 또는 raw key(`x'...'`)를 써서 KDF를 우회하는지는 **아직 미확인** — §4)

## 2. 정적 분석 근거

- 원본 `KakaoTalk.exe`에는 SQLCipher/OpenSSL 문자열이 전혀 없음 → **패킹/보호됨**. 분석은 기존에 생성된 메모리 덤프 `KakaoTalk_dump_SCY.exe`(+IDA DB)로 수행.
- SQLCipher 디버그 로깅 문자열(`sqlcipherCodecAttach: ...`, `sqlcipher_cipher_ctx_key_derive: ctx->kdf_salt_sz=%d ctx->kdf_iter=%d ...`)이 포함된 4.6.x 빌드.
- 앱 레벨 문자열:
  - `ATTACH DATABASE ? as CHATLISTDB KEY ?` (`TalkChatTokenDB`) — 다른 DB를 키와 함께 attach → DB마다 키가 다를 가능성.
  - `DbLibraryMigration::SqlCipherMigration` (`src\libKakaoTalkCore\data\...`):
    - `Failed to open legacy database {}` / `Failed to set legacy key for {}`
    - `Failed to generate new key for {}: {}`
    - `ATTACH DATABASE ? AS newDb KEY ?` → `SELECT sqlcipher_export('newDb')` → `DETACH DATABASE newDb`
    - `Failed to move ikm: {}`, `Failed to move key store: {}`, `Failed to remove key store file`, `Failed to remove backup ikm file`
    - 로그 파일명 `db_library_migration_result_{:%Y%m%d_%H%M%S}.log`

## 3. 해석 (가설)

25.7.2 이상에서 레거시(자체 암호화) DB를 SQLCipher로 이관하면서:
1. 레거시 키로 구 DB를 열고,
2. **DB별 신규 키를 생성**하여 `sqlcipher_export`로 새 SQLCipher DB 생성,
3. 신규 키들은 **key store 파일**에 저장되고, key store는 **ikm(input key material) 파일**로부터 유도된 키(HKDF 류 추정)로 보호되는 구조로 보임.

즉 복호화 경로는 `ikm → (KDF) → key store 복호 → DB별 SQLCipher key` 일 가능성이 높다.
이 기기 데이터 디렉터리 최상위에는 ikm/key store로 보이는 파일명이 바로 보이지 않음(위치·이름 추가 확인 필요).

## 4. 다음 단계 (미완)

1. **정적**: `SqlCipherMigration` 및 DB 오픈 함수에서 `sqlite3_key_v2` 호출부 역추적 → 키 생성/로드 함수, key store·ikm 파일 경로, ikm의 출처(기기 고유값/DPAPI 등) 확인.
2. **동적**: 실행 중 프로세스에서 `sqlite3_key_v2`(또는 `sqlcipher_codec_ctx_set_pass`)에 BP → 각 .edb의 키(passphrase vs raw key 여부, 길이) 캡처. `sqlcipher_cipher_ctx_key_derive` 진입 시 `kdf_iter` 값 확인.
3. 캡처한 키로 SQLCipher 4 기본 설정에서 `PRAGMA key` → `SELECT count(*) FROM sqlite_master` 검증.
