# tagtagyeah
文献にタグをつけ、検索する web アプリを作る

# API

## POST /tag
### 説明
タグの登録
user_id, name が同じ場合、追加で登録されないが成功となる。

### パラメータ
- user_id: ユーザー ID、int64 型
- name: タグ名、50 バイト以下の文字列

## POST /tag/:id
### 説明
タグ名の変更

### パラメータ
- name: タグ名、50 バイト以下の文字列

# TODO
user_id, name が同じ場合、200 以外を返したい。

