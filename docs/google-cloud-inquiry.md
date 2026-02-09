Google Cloud ご担当者様

Google Cloudハッカソン参加にあたり、AIアプリ向け脆弱性検査ツール「Threat Drill」でのGemini API利用がProhibited Use Policy上問題ないか確認させてください。

本ツールは開発者自身のサンドボックス上のAIアプリに対し、Red Team（擬似攻撃）とBlue Team（防御検証）で検査を自動化します。Red Teamではプロンプトインジェクション・脱獄攻撃・SQLi・XSS等の擬似攻撃を実行します。

Geminiの用途は検査項目の優先順位判断とCVE情報からの検査観点提案のみで、攻撃コード生成は行いません。

悪用防止策として検査URLをlocalhost・プライベートIP・GCPサンドボックスに限定し、外部への実行はAPI側で拒否しています。

問題がある場合、Geminiは防御側のみに限定しRed TeamはローカルLLMを使う構成も検討中です。

上野 闘士／情報処理安全確保支援士
