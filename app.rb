require "sinatra"
require "sqlite3"
require "slim"
require "bcrypt"
require "sinatra/reloader"
require "./model.rb"

enable :sessions

public_routes = [
  "/login",
  "/signup",
]

before do
  # redirect to login if user is trying to access route that requires user authentication
  if !(public_routes.include? request.path_info) && !session[:user_id]
    redirect("/login")
  elsif request.path_info.match(/\/groups\/\d+\/\w+/)
    # for /groups/id/edit, /groups/id/roles etc
    if (!user_is_owner_of_group(params[:group_id], session[:user_id]))
      return "Permission denied"
    end
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
  def groups(user_id = params[:user_id])
    return get_groups_of_user(user_id)
  end

  def members(group_id = params[:group_id])
    return get_members_in_group(group_id)
  end

  def role(role_id = params[:role_id])
    return get_role(role_id)
  end
end

# END HELPERS

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

  begin
    login_user(username, password)
  rescue => exception
    return exception.message
  else
    redirect("/")
  end
end

get("/signup") do
  slim(:signup)
end

post("/users/new") do
  username = params[:username]
  password = params[:password]
  confirm_password = params[:confirm_password]

  begin
    register_user(username, password, confirm_password)
  rescue => exception
    return exception.message
  else
    redirect("/")
  end
end

post("/groups") do
  group_name = params[:name]
  user_id = session[:user_id]

  create_group(user_id, group_name)

  redirect("/")
end

get("/groups/new") do
  slim(:"groups/new")
end

get("/groups/{group_id}") do
  group_id = params[:group_id]
  user_id = session[:user_id]

  group = get_group_by_id(group_id)
  messages = get_messages_in_group(group_id)

  slim(:"groups/show", locals: { group: group, messages: messages })
end

post("/messages") do
  group_id = params[:group_id]
  message = params[:message]
  user_id = session[:user_id]

  create_message_in_group(group_id, user_id, message)

  redirect("/groups/#{group_id}")
end

post("/groups/{group_id}/messages/{message_id}/delete") do
  group_id = params[:group_id]
  message_id = params[:message_id]
  user_id = session[:user_id]

  message = get_message_by_id(message_id)

  # check if message is sent by user trying to delete it
  if (message["user_id"] == user_id)
    delete_message(message_id)
    redirect("/groups/#{group_id}")
  else
    return "You don't have permission to delete message"
  end
end

get("/groups/{group_id}/edit") do
  group_id = params[:group_id]

  # check if user is owner of group
  group_roles = get_roles_in_group(group_id)

  slim(:"groups/edit", locals: { group_roles: group_roles })
end

post("/groups/{group_id}/update") do
  new_member_username = params[:new_member_username]
  group_id = params[:group_id]

  add_member_to_group(group_id, new_member_username)

  redirect("/groups/#{group_id}")
end

get("/groups/:group_id/roles") do
  group_id = params[:group_id]

  roles = get_roles_in_group(group_id)

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

  create_role(group_id, title, can_delete, can_kick)

  redirect("/groups/#{group_id}/roles")
end

get("/groups/:group_id/roles/:role_id") do
  slim(:"roles/show")
end

get("/groups/:group_id/roles/:role_id/edit") do
  slim(:"roles/edit")
end

post("/groups/:group_id/roles/:role_id/update") do
  group_id = params[:group_id]
  role_id = params[:role_id]

  title = params[:title]
  can_delete = params[:can_delete]
  can_kick = params[:can_kick]

  update_role(role_id, title, can_delete, can_kick)

  redirect("/groups/#{group_id}/roles/#{role_id}/edit")
end

post("/groups/:group_id/roles/:role_id/destroy") do
  # TODO: delete role and remove role from all users with the role
  role_id = params[:role_id]
  group_id = params[:group_id]

  delete_role_in_group(group_id, role_id)

  redirect("/groups/#{group_id}/roles")
end

post("/groups/:group_id/members/:user_id/update") do
  role_id = params[:role_id]
  group_id = params[:group_id]
  user_id = params[:user_id]

  update_role_of_user_in_group(group_id, user_id, role_id)

  redirect("/groups/#{group_id}/edit")
end
