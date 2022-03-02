require "sinatra"
require "sqlite3"
require "slim"
require "bcrypt"
require "sinatra/reloader"

enable :sessions

public_routes = [
  "/login",
  "/signup",
]

before do
  # redirect to login if user is trying to access route that requires user authentication
  if !(public_routes.include? request.path_info) && !session[:user_id]
    redirect("/login")
  elsif request.path_info.match(/\/groups\/+?\d+/)

    # check if user is a member of the group if route is /groups/:group_id
    group_id = params[:group_id]
    user_id = session[:user_id]

    db = connect_db()

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
  end

  # TODO: check if creator for certain routes
end

# START HELPERS

helpers do
  def groups
    db = connect_db()
    user_id = session[:user_id]

    if (!user_id)
      # return empty if not logged in
      return []
    end

    # get groups where user is a member of
    groups = db.execute("SELECT 
                        *
                      FROM
                        chat_groups
                      INNER JOIN groups_users
                      ON (chat_groups.id = groups_users.group_id)
                      WHERE groups_users.user_id = ?
                      ", user_id)

    return groups
  end

  def members(group_id = params[:group_id])
    if (!group_id)
      return []
    end

    db = connect_db()

    members = db.execute("SELECT
                          users.id,
                          users.username,
                          users_group_roles.group_role_id
                        FROM
                          users
                        INNER JOIN groups_users
                          ON groups_users.user_id = users.id
                        LEFT JOIN users_group_roles
                          ON users_group_roles.user_id = users.id
                          AND users_group_roles.group_role_id = (SELECT id FROM group_roles WHERE group_roles.group_id = ?)
                        WHERE groups_users.group_id = ?
                        ", group_id, group_id)

    return members
  end
end

# END HELPERS

# START FUNCTIONS

def connect_db(path = "db/database.db")
  db = SQLite3::Database.new(path)
  db.results_as_hash = true

  return db
end

# END FUNCTIONS

# START ROUTES

get("/") do
  user_id = session[:user_id]

  slim(:"groups/index")
end

get("/login") do
  slim(:login)
end

post("/login") do
  username = params[:username]
  password = params[:password]

  db = connect_db()

  # get user with username
  user = db.execute("SELECT * FROM users WHERE username = ?", username).first

  if user
    # compare password
    pwd_digest = user["pwd_digest"]

    if BCrypt::Password.new(pwd_digest) == password
      # login user
      session[:user_id] = user["id"]
      redirect("/")
    else
      return "Invalid password or username"
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

  db = connect_db()

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

  db = connect_db()

  # create group
  db.execute("INSERT INTO chat_groups (name, creator) VALUES (?, ?)", group_name, user_id)
  group_id = db.last_insert_row_id

  puts "GROUP:"
  puts group_id

  # add users to the group
  db.execute("INSERT INTO groups_users (user_id, group_id) VALUES (?, ?)", user_id, group_id)

  redirect("/")
end

get("/groups/new") do
  slim(:"groups/new")
end

get("/groups/{group_id}") do
  group_id = params[:group_id]
  user_id = session[:user_id]

  db = connect_db()

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
  group_id = params[:group_id]
  message = params[:message]
  user_id = session[:user_id]

  db = connect_db()

  # create message
  db.execute("INSERT INTO messages (message, group_id, user_id) VALUES (?, ?, ?)", message, group_id, user_id)

  redirect("/groups/#{group_id}")
end

get("/groups/{group_id}/edit") do
  group_id = params[:group_id]
  role_id = params[:role_id]

  db = connect_db()

  group_roles = db.execute("SELECT * FROM group_roles WHERE group_id = ?", group_id)

  slim(:"groups/edit", locals: { group_roles: group_roles })
end

post("/groups/{group_id}/update") do
  new_member_username = params[:new_member_username]
  group_id = params[:group_id]

  puts "EDITING GROUP #{group_id}"

  db = connect_db()

  # get the user id of user with username
  user = db.execute("SELECT id FROM users WHERE username = ?", new_member_username).first

  if (!user)
    # display error message
    return "No user found with username #{new_member_username}"
  end

  user_id = user["id"]
  puts "Checking if users #{user_id} exists in group #{group_id}"

  # check if user is already a member of the group
  is_member = db.execute("SELECT
              1
              FROM groups_users
              WHERE user_id = ?
              AND group_id = ?", user_id, group_id).first

  if (is_member)
    # display error message
    return "User is already a member of the group"
  end

  puts "Adding user #{user_id} to group #{group_id}"
  db.execute("INSERT INTO groups_users (user_id, group_id) VALUES (?, ?)", user_id, group_id)

  redirect("/groups/#{group_id}")
end

get("/groups/:group_id/roles") do
  db = connect_db()
  group_id = params[:group_id]

  roles = db.execute("SELECT * FROM group_roles WHERE group_id = ?", group_id)

  slim(:"roles/index", locals: { roles: roles })
end

get("/groups/:group_id/roles/new") do
  slim(:"roles/new")
end

post("/groups/:group_id/roles") do
  group_id = params[:group_id]

  title = params[:title]
  can_delete = params[:can_delete]
  can_kick = params[:can_kick]

  db = connect_db()

  db.execute("INSERT INTO group_roles (group_id, title, canDelete, canKick) VALUES (?, ?, ?, ?)", group_id, title, can_delete, can_kick)

  redirect("/groups/#{group_id}/roles")
end

get("/groups/:group_id/roles/:role_id") do
  slim(:"/roles/show")
end

get("/groups/:group_id/roles/:role_id/edit") do
  slim(:"/roles/edit")
end

get("/groups/:group_id/roles/:role_id/update") do
  # TODO: update group role
end

get("/groups/:group_id/roles/:role_id/destroy") do
  # TODO: delete role and remove role from all users with the role
end

post("/groups/:group_id/members/:user_id/update") do
  role_id = params[:role_id]
  group_id = params[:group_id]
  user_id = params[:user_id]

  db = connect_db()

  current_role_id = db.execute("SELECT 
                                users_group_roles.group_role_id
                              FROM 
                                users_group_roles
                              LEFT JOIN users
                                ON users.id = users_group_roles.user_id
                              INNER JOIN group_roles
                                ON group_roles.id = users_group_roles.group_role_id
                              WHERE group_roles.group_id = ?
                              AND users.id = ?
                              ", group_id, user_id).first

  if (current_role_id)
    if !role_id
      # update role_id
      db.execute("UPDATE users_group_roles
                SET group_role_id = ?
                WHERE users_group_roles.group_role_id =
                  (SELECT id 
                    FROM group_roles 
                  WHERE group_id = ?)
                AND user_id = ?", role_id, group_id, user_id)
    else
      # delete role from user
      db.execute("DELETE FROM users_group_roles
                  WHERE users_group_roles.group_role_id = (SELECT id FROM group_roles WHERE group_id = ?)
                  AND user_id = ?", group_id, user_id)
    end
  else
    # create new relation
    db.execute("INSERT INTO users_group_roles (group_role_id, user_id) VALUES (?, ?)", role_id, user_id)
  end

  redirect("/groups/#{group_id}/edit")
end
