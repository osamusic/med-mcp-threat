# Windows クリーンインストールガイド

## 問題の状況

```
WARNING: Ignoring invalid distribution ~cp-threat-extraction
WARNING: Skipping mcp-threat-extraction as it is not installed.
```

このエラーは、以前のインストールが不完全に残っているか、破損したパッケージが存在することを示しています。

## クリーンアップ手順

### 1. 手動でパッケージディレクトリを削除

```powershell
# Pythonのsite-packagesディレクトリを確認
python -c "import site; print(site.getsitepackages())"

# 例: C:\Users\[USERNAME]\AppData\Local\Programs\Python\Python312\Lib\site-packages
```

以下のディレクトリとファイルを手動で削除してください：

```
C:\Users\[USERNAME]\AppData\Local\Programs\Python\Python312\Lib\site-packages\
├── mcp_threat_extraction/          (ディレクトリ全体を削除)
├── mcp_threat_extraction-*.dist-info/  (該当するディレクトリを削除)
├── ~cp-threat-extraction/           (破損したディレクトリを削除)
└── mcp-threat-extraction.*          (関連ファイルを削除)
```

### 2. Scriptsディレクトリからコマンドを削除

```powershell
# Scriptsディレクトリを確認
where mcp-threat-extraction
```

以下のファイルを削除：
```
C:\Users\[USERNAME]\AppData\Local\Programs\Python\Python312\Scripts\
├── mcp-threat-extraction.exe
└── mcp-threat-extraction-script.py
```

### 3. キャッシュをクリア

```powershell
pip cache purge
```

### 4. 必須依存関係をインストール

```powershell
pip install sentence-transformers
```

### 5. 新しいパッケージをインストール

```powershell
# v0.3.0をダウンロード後
pip install mcp_threat_extraction-0.3.0-py3-none-any.whl
```

### 6. 動作確認

```powershell
# インストール確認
pip show mcp-threat-extraction

# コマンド確認
mcp-threat-extraction
```

## 完全なPowerShellスクリプト

以下のスクリプトを`clean_install.ps1`として保存して実行：

```powershell
# mcp-threat-extraction クリーンインストールスクリプト

Write-Host "🧹 MCP Threat Extraction クリーンアップを開始します..." -ForegroundColor Yellow

# 1. 現在の状況を確認
Write-Host "📋 現在の状況を確認..." -ForegroundColor Cyan
pip show mcp-threat-extraction

# 2. site-packagesの場所を取得
$sitePackages = python -c "import site; print(site.getsitepackages()[0])"
Write-Host "📁 Site-packages: $sitePackages" -ForegroundColor Green

# 3. 関連ディレクトリとファイルを削除
Write-Host "🗑️  関連ファイルを削除..." -ForegroundColor Red
$patterns = @(
    "mcp_threat_extraction",
    "mcp_threat_extraction-*.dist-info",
    "~cp-threat-extraction"
)

foreach ($pattern in $patterns) {
    $fullPattern = Join-Path $sitePackages $pattern
    Get-ChildItem $fullPattern -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
    Write-Host "  削除: $pattern" -ForegroundColor Gray
}

# 4. Scripts内のコマンドを削除
$scriptsDir = Split-Path (Get-Command python).Source
$scriptFiles = @(
    "mcp-threat-extraction.exe",
    "mcp-threat-extraction-script.py"
)

foreach ($file in $scriptFiles) {
    $fullPath = Join-Path $scriptsDir $file
    if (Test-Path $fullPath) {
        Remove-Item $fullPath -Force
        Write-Host "  削除: $file" -ForegroundColor Gray
    }
}

# 5. キャッシュクリア
Write-Host "🧼 キャッシュをクリア..." -ForegroundColor Cyan
pip cache purge

# 6. 必須依存関係をインストール
Write-Host "📦 必須依存関係をインストール..." -ForegroundColor Cyan
pip install sentence-transformers

# 7. パッケージファイルの確認
$packageFile = "mcp_threat_extraction-0.3.0-py3-none-any.whl"
if (Test-Path $packageFile) {
    Write-Host "✅ パッケージファイルが見つかりました: $packageFile" -ForegroundColor Green
    pip install $packageFile
    
    Write-Host "🎉 インストール完了！動作確認中..." -ForegroundColor Green
    pip show mcp-threat-extraction
    mcp-threat-extraction
} else {
    Write-Host "❌ パッケージファイルが見つかりません: $packageFile" -ForegroundColor Red
    Write-Host "   GitHubからダウンロードしてください。" -ForegroundColor Yellow
}
```

## トラブルシューティング

### アクセス許可エラーが発生する場合

管理者権限でPowerShellを実行：

```powershell
# PowerShellを管理者として実行
Start-Process PowerShell -Verb RunAs
```

### パッケージファイルが見つからない場合

GitHubからダウンロード：
```
https://github.com/osamusic/med-threat/releases
```

または直接ビルド：
```powershell
git clone https://github.com/osamusic/med-threat.git
cd med-threat/mcp-threat-extraction
pip install build
python -m build
pip install dist/mcp_threat_extraction-0.3.0-py3-none-any.whl
```