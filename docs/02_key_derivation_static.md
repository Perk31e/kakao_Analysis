# KakaoTalk PC 26.8.2 — SQLCipher 키 생성/주입 경로 (정적 분석)

분석 대상: `KakaoTalk_dump_SCY.exe` (Themida 언팩 덤프, IDA/REA). 이미지 base `0x140000000`.
주의: 본체는 Themida로 보호됨(`.themida`/`.boot` 섹션). 모든 주소는 덤프 기준.

## 핵심 결론

KakaoTalk은 각 .edb를 **DB별 raw 256-bit 키**로 연다. 키 유도 흐름:

```
(비밀 입력) + (DB별 32바이트 salt)  --SHA256 기반 KDF-->  32바이트 키
       |
       v
ATTACH DATABASE ? AS <db> KEY x'<64 hex>'      (SQLCipher raw key)
```

즉 패스프레이즈가 아니라 **raw key**를 쓰므로, 이 32바이트를 알아내면
`PRAGMA key = "x'<64hex>'"` 로 SQLCipher 4 기본 설정에서 바로 복호화가 된다.
(raw key 사용 시 SQLCipher는 PBKDF2 패스프레이즈 유도를 건너뛰지만, salt는 여전히 DB 헤더 첫 16바이트, HMAC 키는 raw key에서 1라운드로 유도)

## 함수별 근거

| 주소 | 역할 | 근거 |
|---|---|---|
| `sub_141C03D90` | 레거시→SQLCipher DB 1개 이관 | `"ATTACH DATABASE ? AS newDb KEY ?"`, `sqlcipher_export('newDb')` 바인딩/실행 |
| `sub_141C02BC0` | 레거시 DB 열기 + legacy key 설정 | `"Failed to open legacy database"`, `"Failed to set legacy key"` |
| `sub_141CCAC20` | **KEY 인자(`x'..'`) 조립** | `strcpy(&v45,"x'")` 후 32바이트 버퍼(`v42..v43`)를 바이트당 2 hex로 포매팅(`a02x`), 마지막에 `'` 추가 → `x'<64 hex>'` |
| `sub_141CCB9A0` | **키 유도 KDF** | 파라미터 배열에 `"sha256"`(len 6), 입력 비밀(`a3`), salt `struct+64`(32바이트), 출력 32바이트. `a6==1`이면 신규 32바이트 생성(새 DB 생성 경로), `a6==2`면 기존값 유도 |
| `sub_141CCC710` | KDF 입력(비밀/salt) 구성 | 32바이트 블록들(`a1+72`, `a1+104`, `a1+136`)을 모아 KDF로 전달 |
| `sub_141CC9510` | 32바이트 입력 1건 스트림 처리 | `sub_1409089A0(.,.,32)` 등 32바이트 단위 |

문자열 오프셋(파일): `"ATTACH DATABASE ? AS newDb KEY ?"`=0x29d89f8, `"SELECT sqlcipher_export('newDb')"`=0x29d8b18,
`"Failed to generate new key for {}"`=0x29d89a8, `"Failed to set legacy key for {}"`=0x29d8980.

## 아직 확정 못한 것 (동적 분석 필요)

1. **KDF 정확한 종류**: 파라미터가 (알고리즘명="sha256", 비밀, salt 32B, 출력 32B)이고 반복횟수가 정적으로 안 보임
   → PBKDF2가 아니라 **HKDF 또는 keyed-hash(HMAC)** 가능성. x64dbg로 `sub_141273EA0` 진입 시 실제 OpenSSL 호출(`PKCS5_PBKDF2_HMAC` vs `EVP_PKEY_derive`/HKDF)로 확정 필요.
2. **비밀 입력(ikm)의 출처**: `sub_141CCC710`에 모이는 `a1+72/104/136` 블록이 어디서 채워지는지 — 기기 고유값/DPAPI/상수 중 무엇인지. 이게 복호화 가능성의 핵심.
3. **salt의 저장 위치**: DB별 32바이트 salt가 key store 파일에 있는지, DB 헤더(첫 16B)와 어떤 관계인지.

## 다음 단계

- 동적: 실행 중 KakaoTalk에 `sqlite3_key_v2` / `sub_141CCB9A0` BP → DB별 32바이트 키와 salt, KDF 입력 캡처.
- 캡처한 raw key로 `PRAGMA key="x'...'"` + SQLCipher4 기본값 복호화 검증.
