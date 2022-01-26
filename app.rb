require "sinatra"
require "sqlite3"
require "slim"
require "bcrypt"

enable :sessions

get("/") do
  return "test"
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
