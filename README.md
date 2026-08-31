# TOY-RSA (1985 Edition)

⚠️ WARNING: DO NOT USE IN PRODUCTION ⚠️

このRSA実装はWeb小説用の歴史的・エンタメ的実証コード（1985年当時の水準）であり、現代のセキュリティ要件を満たしていません。致命的な脆弱性が含まれています。絶対に実際の製品やシステムに組み込まないでください。

This is a historical recreation for entertainment purposes based on publicly available techniques from around 1985. It is intentionally insecure by modern standards and must not be used in any production system or product.

---

Web小説『週刊「RSAを作る」創刊号はDES実装のための写経ほか』の作中、主人公（TOY）が実装したRSA+DESハイブリッド暗号の実証コードです。

当時のPC環境（16ビット）と、1985年時点でアクセス可能だった論文・仕様書を用いて「いかにして実用的な速度を確保するか」をテーマに設計されています。

## Technical Highlights

作中の時代考証に合わせ、以下のアルゴリズムと制約で実装されています。

* **RSA Optimization:**
    * Peter L. Montgomeryの論文（1985年）に基づくモンゴメリ・リダクションの適用。
    * 中国人剰余定理（CRT）による秘密鍵演算（復号）の高速化。
* **CSPRNG (暗号論的擬似乱数生成器):** ANSI X9.17-1985 Appendix C をベースにしたDES組み込み乱数生成器。
* **Digest / Integrity:** MMO（Matyas-Meyer-Oseas）構成に基づく独自の一方向関数

## For Readers

リポジトリはWeb小説の公開進捗に合わせてコードがpushされていきます。TOYが何を実装したのかを一緒にお楽しみください。

リアルタイムではないからと言って悲しまなくても大丈夫。各話に対応したタグがつけられています。読み進めながら切り替えていくことで何を実装していたのか追体験ができるかと思います。
