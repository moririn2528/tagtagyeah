# tagtagyeah
文献にタグをつけ、検索する web アプリを作る

https://tagtagyeah.herokuapp.com/

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

## GET /tag
### 説明
タグの検索、一覧取得

### パラメータ
- user_id: ユーザー ID、int64 型
- search_phrase: 検索文字列、prefix が完全一致となるタグを返す

# JSON
## Tag
- id: タグの id、int64 型
- user_id: このタグを登録したユーザー id、int64 型
- name: タグ名、50 バイト以下の文字列

## Unit
- name: 登録名、文字列
- url: 登録URL、文字列
- tags: これに結び付けたタグ、Tag 型の配列

# TODO
## POST /tag
- user_id, name が同じ場合、200 以外を返したい。

## GET /tag
- 毎回 select が実行される、search_phrase だけ変わったとき、早くかえしたい。
- 前方完全一致になっている、N グラムとかの検索アルゴリズムを入れる

