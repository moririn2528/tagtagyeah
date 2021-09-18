# tagtagyeah
文献にタグをつけ、検索する web アプリを作る

https://tagtagyeah.herokuapp.com/

# API
## POST /register
### 説明
ユーザー名、パスワード、メールアドレスを登録する。

### パラメータ
- username: ユーザー名、20 バイト以下英数字のみの文字列
- password: パスワード、100 バイト以下の文字列、ハッシュ済みのものにすること
- email: メールアドレス、100 バイト以下の文字列、

## GET /auth
### 説明
メール認証 (メールに送信されているリンク)

### パラメータ
- uuid: uuid

## POST /auth
### 説明
認証メール送信、ユーザーにつき 1 日 10 通まで送信可能

### パラメータ
- username: ユーザー名

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
- uuid
- name: タグ名、50 バイト以下の文字列

## GET /tag
### 説明
タグの検索、一覧取得

### パラメータ
- uuid
- search_phrase: 検索文字列、prefix が完全一致となるタグを返す

### 返り値
- Tag(JSON) の配列

## PUT /tag
### 説明
タグの更新

### パラメータ
- uuid
- id: タグ id
- name: タグ名

### 返り値
JSON 
- id: タグ id、数値

## DELETE /tag/:id
### 説明
タグの削除

### パラメータ
- id: タグ id
- uuid (クエリパラメータ)

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
name, url のうち少なくとも 1 つは付けること

### 返り値
JSON 
- id: Unit id、数値

## PUT /unit
### 説明
Unit の更新

### パラメータ
- uuid
- tags: タグ id をコンマ区切りでつなげた文字列、省略可
- name: 名前、省略可
- url : URL、省略可
tags, name, url のうち少なくとも 1 つは付けること

## DELETE /unit
### 説明
Unit の削除

### パラメータ
- id: Unit id
- uuid (クエリパラメータ)


## GET /user
### 説明
ユーザー情報をかえす

## パラメータ
- uuid

## 返り値
JSON 型 User

## PUT /user
### 説明
ユーザー情報の更新、メールアドレスを更新する際は認証メール送信

## パラメータ
- uuid
- username: ユーザー名、省略可
- password: パスワード、省略可
- email: メールアドレス、省略可
username, password, email のうち一つは使うこと

## DELETE /user/:uuid
### 説明
ユーザーの削除

## http ステータス
- 成功時 200
- 入力パラメータのエラー 400
- uuid 有効期限切れ 403 "uuid is expired"
- ユーザーが登録していない unit, tag に対する変更 403
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

# パラメータ
- GET: QueryParam
- PUT, POST: FormValue
- DELETE: (Param)

# TODO
## POST5
- id を返してほしい

## POST /tag
- user_id, name が同じ場合、200 以外を返したい。

## GET /tag
- 毎回 select が実行される、search_phrase だけ変わったとき、早くかえしたい。
- 前方完全一致になっている、N グラムとかの検索アルゴリズムを入れる

## その他
ユーザー名からメール送信でパスワード再設定できるようにする(フロントと相談)
