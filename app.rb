require "sinatra"
require "sqlite3"
require "slim"
require "bcrypt"

enable :sessions

def validate_user()
  user_id = session[:user_id]

  if !user_id
    redirect("/login")
  end
end

get("/") do
  validate_user()

  db = SQLite3::Database.new("db/database.db")
  db.results_as_hash = true

  user_id = session[:user_id]

  # get groups where user is a member of
  groups = db.execute("SELECT 
                        groups_users.group_id,
                        chat_groups.name
                      FROM
                        groups_users
                        INNER JOIN chat_groups ON (groups_users.group_id = chat_groups.id)
                      ")

  my_groups = db.execute("SELECT * FROM chat_groups WHERE creator = ?", user_id)

  slim(:"groups/index", locals: { groups: groups, my_groups: my_groups })
end

get("/login") do
  slim(:login)
end

post("/login") do
  username = params[:username]
  password = params[:password]

  db = SQLite3::Database.new("db/database.db")
  db.results_as_hash = true

  # get user with username
  user = db.execute("SELECT * FROM users WHERE username = ?", username).first

  if user
    # compare password
    pwd_digest = user["pwd_digest"]

    if BCrypt::Password.new(pwd_digest) == password
      # login user
      session[:user_id] = user["id"]
      redirect("/")
    end
  else
    # show error message: invalid username
    return "Invalid username"
  end
end

get("/signup") do
  slim(:signup)
end

post("/users/new") do
  username = params[:username]
  password = params[:password]
  confirm_password = params[:confirm_password]

  # validate password
  if !(password == confirm_password)
    # show error message: passwords not matching
    return "Passwords not matching"
  end

  db = SQLite3::Database.new("db/database.db")

  # check for existing users
  user = db.execute("SELECT * FROM users WHERE username = ?", username).first
  if user
    # show error message: user exists already
    return "Username is already in use"
  end

  # one-way encrypt password
  pwd_digest = BCrypt::Password.create(password)

  # create new user
  db.execute("INSERT INTO users (username, pwd_digest) VALUES (?, ?)", username, pwd_digest)

  # get id of new user
  user_id = db.execute("SELECT id FROM users WHERE username = ?", username)

  # save user_id in session
  session[:user_id] = user_id

  redirect("/")
end

post("/groups") do
  group_name = params[:name]
  user_id = session[:user_id]

  db = SQLite3::Database.new("db/database.db")

  # create group
  db.execute("INSERT INTO chat_groups (name, creator) VALUES (?, ?)", group_name, user_id)

  redirect("/")
end

get("/groups/new") do
  slim(:"groups/new")
end

get("/groups/{group_id}") do
  validate_user()

  group_id = params[:group_id]
  user_id = session[:user_id]

  db = SQLite3::Database.new("db/database.db")
  db.results_as_hash = true

  # check if user is a member of group
  group_user = db.execute("SELECT
              1
              FROM groups_users
              WHERE user_id = ?
              AND group_id = ?", user_id, group_id)

  if (!group_user)
    # show error message: unauthorized
    return "You are not a member of the group"
  end

  # get messages from group with sender username
  messages = db.execute("SELECT 
                          messages.id,
                          users.username,
                          messages.message
                        FROM messages
                        LEFT JOIN users
                        ON messages.user_id = users.id
                        WHERE group_id = ?
                        ", group_id)

  group = db.execute("SELECT * FROM chat_groups WHERE id = ?", group_id).first

  slim(:"groups/show", locals: { group: group, messages: messages })
end

post("/messages") do
  validate_user()

  group_id = params[:group_id]
  message = params[:message]
  user_id = session[:user_id]

  db = SQLite3::Database.new("db/database.db")

  # create message
  db.execute("INSERT INTO messages (message, group_id, user_id) VALUES (?, ?, ?)", message, group_id, user_id)

  redirect("/groups/#{group_id}")
end
