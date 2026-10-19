# KakaoTalk PC 26.8.2 — SQLCipher 키 생성/주입 경로 (정적 분석)

분석 대상: `KakaoTalk_dump_SCY.exe` (Themida 언팩 덤프, IDA/REA). 이미지 base `0x140000000`.
주의: 본체는 Themida로 보호됨(`.themida`/`.boot` 섹션). 모든 주소는 덤프 기준.

> 🔄 **갱신(2026-10-19):** 이 문서의 정적 추정은 이후 동적 분석으로 상당 부분 확정/정정됐다.
> 핵심: `sub_141CCB9A0`에 보이던 `"sha256"` 파라미터는 맞지만 **KDF 본체는 Themida VM으로 가상화**되어
> 정적 복원 불가. `sub_141CCC710`이 모으는 블록 중 `ctx+0xE0`는 **비밀이 아니라 OpenSSL 컨텍스트
> 핸들**이다. 최종적으로 KDF 재현 대신 SQLCipher가 메모리에 남기는 **keyspec을 직접 포착**해 복호화를
> 검증 완료했다. 상세·정정은 `docs/04`(런타임)과 `re/pseudo/sub_141CCAC20_key_assembly.md` 참조.

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

## 정적 미확정 항목 → 동적 분석 결과 (해결 상태)

1. **KDF 정확한 종류** — ❌ **복원 불가로 확정**. `sub_141CCB9A0`은 32B 출력 버퍼를 잡은 뒤
   `jmp 0x14444f323`로 **Themida VM(0x144xxxxxx)** 에 진입한다. 알고리즘(HKDF/HMAC/PBKDF2)을 정적으로
   읽을 수 없음. → 복호화는 KDF 재현이 아니라 결과 keyspec 포착으로 달성(`docs/04` §8).
2. **비밀 입력(ikm)의 출처** — ✅ 런타임 확정. 키 매니저 싱글턴 `*(void**)0x142E42068`의
   `ctx+0x68`(SECRET_A, 32B)·`ctx+0x120`(32B)·라벨 `ctx+0x100`("v2:")가 입력. `ctx+0x48/0x68/0x88`
   중 `ctx+0xE0`은 **OpenSSL 컨텍스트 핸들(비밀 아님)**. 값은 `mss.dat` 유래로 **재시작 불변**(검증됨).
3. **salt 저장 위치** — ✅ 확정. DB별 32B salt는 **키 매니저 맵의 노드 `node+0x30`** 에 상주.
   이는 SQLCipher 파일 헤더의 16B kdf_salt와 **다른 값**(파일 salt는 HMAC 키 유도용).

## 최종 경로 (요약)

- 정적: 키 조립 함수 `sub_141CCAC20` 완전 해독(`re/pseudo/sub_141CCAC20_key_assembly.md`).
  단 KDF 본체는 Themida VM으로 막힘.
- 복호화: 실행 중 프로세스 메모리에서 SQLCipher **keyspec `x'<키><솔트>'` 외부 스캔** → 27개 DB
  page‑1 검증 + `emoticon.edb` 전체 복호화(`integrity_check=ok`). → `docs/04` §8, `README.md`.
