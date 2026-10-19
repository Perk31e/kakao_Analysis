# KakaoTalk PC 26.8.2 — 평상시 DB 오픈 경로 & 키 저장소 파일

> 🔄 **갱신(2026-10-19):** 아래 "SHA256-KDF(ikm, salt)" 추정은 동적 분석으로 정정됨 —
> KDF 본체는 **Themida VM 가상화**라 알고리즘 복원 불가, `mss.dat`를 푸는 과정도 추적 불가.
> 대신 런타임 키 매니저(`*(void**)0x142E42068`)에 **복호화된 키 재료가 상주**하고, 더 결정적으로
> SQLCipher가 **열린 DB마다 keyspec `x'<키><솔트>'`를 메모리에 보관**하므로 이를 외부 스캔해 복호화를
> 완료했다(디버거 불필요). 상세: `docs/04` §8, `README.md`. 아래 파일 분류(§키 저장소 추정)는 유효.

## 평상시(스틸스테이트) 오픈 경로

```
sub_141BA7F40(정상 DB 오픈)
  └ ctx = sub_141BA8180()        // 키 재료를 들고 있는 싱글턴/컨텍스트 객체
  └ sub_141CCAC20(ctx, out, dbName)   // ctx의 키 재료(+256/+272)로 KEY x'<64hex>' 조립
         └ sub_141CCC710 → sub_141CCB9A0  // SHA256 기반 KDF로 DB별 32바이트 키 산출
```

- 키 재료는 `sub_141BA8180()`가 돌려주는 컨텍스트 객체 안에 있다(오프셋 +72/+104/+136 = KDF 입력, +256/+272 = 키 조립 입력).
- 마이그레이션 경로(`sub_141C03D90`)와 **동일한** 키 조립 함수(`sub_141CCAC20`)를 공유 → 신규/기존 DB 모두 같은 raw-key 스킴.

## 키 저장소 추정 파일 (이 기기)

데이터 디렉터리에 `ikm`/`keystore`라는 이름의 파일은 없다(마이그레이션 코드가 옮긴 뒤 삭제하는 레거시 파일명). 신규 스킴의 키 재료 후보:

| 파일 | 크기 | 관찰 | 추정 |
|---|---|---|---|
| `users/<hash>/mss.dat` | 1808 B | 고엔트로피, DPAPI 매직 없음 | **key store(암호화된 키 재료)** 유력 |
| `users/<hash>/profile.dat` | 40 B | 고엔트로피 | 암호화된 소량 데이터 |
| `users/<hash>/labcf.dat` | 80 B | 고엔트로피 | 암호화된 소량 데이터 |
| `users/last_pc_login.dat` | 408 B | 계정 식별자 + 토큰이 평문 | 로그인 캐시(PII 포함, 리포 커밋 금지) |

- `mss.dat`에 DPAPI 블롭 매직(`01000000 d08c9ddf`)이 없음 → Windows DPAPI 직접 사용은 아님.
  즉 ikm(mss.dat을 푸는 키)은 앱 내부 상수 또는 기기 바인딩 값일 가능성. **이게 복호화 가능 여부의 최종 관문.**

## 종합: 복호화에 필요한 것

1. DB별 32바이트 raw key (= SHA256-KDF(ikm계열 비밀, DB별 salt)).
2. raw key만 알면 `PRAGMA key="x'<64hex>'"` + SQLCipher4 기본값으로 복호화 가능.
3. 미해결: KDF 정확한 종류, ikm 비밀의 출처(`sub_141BA8180` 컨텍스트가 어디서 채워지는가), `mss.dat` 포맷.

## 동적 분석 계획 (다음)

x64dbg로 실행 중 KakaoTalk에서:
1. `sub_141CCB9A0`(KDF) 또는 `sqlite3_key_v2` 진입 BP → 각 .edb의 32바이트 키, salt, KDF 입력 비밀 캡처.
2. `sub_141273EA0` 내부에서 실제 호출되는 OpenSSL 함수 확인(PBKDF2 vs HKDF).
3. 캡처한 key로 복호화 PoC 검증.
