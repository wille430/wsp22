# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema.define(version: 0) do
  create_table "chat_groups", force: :cascade do |t|
    t.text "name", null: false
    t.integer "creator", null: false
  end

  create_table "group_roles", force: :cascade do |t|
    t.integer "group_id", null: false
    t.text "title", null: false
    t.integer "canDelete", default: 0
    t.integer "canKick", default: 0
  end

  create_table "groups_users", force: :cascade do |t|
    t.integer "user_id", null: false
    t.integer "group_id", null: false
  end

  create_table "messages", force: :cascade do |t|
    t.text "message"
    t.integer "group_id", null: false
    t.integer "user_id", null: false
  end

  create_table "users", force: :cascade do |t|
    t.text "username", null: false
    t.integer "pwd_digest"
  end

  create_table "users_group_roles", force: :cascade do |t|
    t.integer "user_id", null: false
    t.integer "group_role_id", null: false
  end
end
