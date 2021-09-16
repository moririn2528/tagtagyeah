# tagtagyeah
文献にタグをつけ、検索する web アプリを作る

https://tagtagyeah.herokuapp.com/

# API
## POST /register
### 説明
ユーザー名、パスワード、メールアドレスを登録する。

### パラメータ
- username: ユーザー名、20 バイト以下の文字列
  はじいていないが英数字のみにしてほしい
- password: パスワード、100 バイト以下の文字列、ハッシュ済みのものにすること
- email: メールアドレス、100 バイト以下の文字列、

## GET /auth
### 説明
メール認証 (メールに送信されているリンク)

### パラメータ
- uuid: uuid

## POST /login
### 説明
ユーザー名、パスワードから、UUID が生成される。
UUID の有効期限は 1 日。
メール未認証のときはじかれる。

### パラメータ
- username: ユーザー名、20 バイト以下の文字列
- password: パスワード、100 バイト以下の文字列、ハッシュ済みのものにすること

### 返り値
JSON 型
- uuid: ユーザー uuid、20 文字の文字列

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

## GET /tag
### 説明
タグの検索、一覧取得

### パラメータ
- user_id: ユーザー ID、int64 型
- search_phrase: 検索文字列、prefix が完全一致となるタグを返す

### 返り値
- Tag(JSON) の配列

## GET /unit
### 説明
Unit を tag から検索

### パラメータ
- uuid
- tags: タグ id をコンマ区切りでつなげた文字列、空文字不可

### 返り値
- Unit(JSON) の配列

## POST /unit
### 説明
Unit を作成、タグ付け

### パラメータ
- uuid
- tags: タグ id をコンマ区切りでつなげた文字列
- name: 名前、省略可
- url : URL、省略可

## http ステータス
- 成功時 200
- 入力パラメータのエラー 400
- uuid 有効期限切れ 403
- それ以外のエラー(上ではじけなかった入力エラーや内部エラーなど) 500

# JSON
## Tag
- id: タグの id、int64 型
- user_id: このタグを登録したユーザー id、int64 型
- name: タグ名、50 バイト以下の文字列

## Unit
- id: Unit の id、int64 型
- name: 登録名、文字列
- url: 登録URL、文字列
- tags: これに結び付けたタグ、Tag 型の配列

## User
- id: ユーザー id、int64 型
- uuid: uuid、20 文字の文字列
- name: 名前、文字列
- email: メールアドレス、文字列
- expire_uuid_at: uuid の有効期限

# TODO
## POST /login
- username 英数字のみにする

## POST /tag
- user_id, name が同じ場合、200 以外を返したい。

## GET /tag
- 毎回 select が実行される、search_phrase だけ変わったとき、早くかえしたい。
- 前方完全一致になっている、N グラムとかの検索アルゴリズムを入れる

## GET /unit
- tags 空文字でも可能にする
