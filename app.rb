require 'sinatra'
require 'sqlite3'
require 'slim'
require 'bcrypt'
require 'sinatra/reloader'
require 'sinatra-websocket'
require 'json'
require './model.rb'

include Model

enable :sessions

also_reload './model.rb'

set :server, 'thin'
set :sockets, []

public_routes = [
  '/login',
  '/signup',
  '/users'
]

MAX_LOGIN_ATTEMPTS = 5

before do
  # redirect to login if user is trying to access route that requires user authentication
  if !(public_routes.include? request.path_info) && !session[:user_id]
    redirect('/login')
  elsif public_routes.include? request.path_info && session[:user_id]
    redirect('/')
  end
end

before /(\/groups\/)\d+/ do
  group_id = request.path_info[/(?<=\/groups\/)(\d+)/]
  user_id = session[:user_id]

  if (!user_exists_in_group(group_id, user_id))
    redirect('/login?error=not-a-member')
  else
    pass
  end
end

before /(\/groups\/)\d+(\/members\/)\d+\/destroy/ do
  member_id = request.path_info[/(?<=\/members\/)(\d+)/].to_i
  group_id = request.path_info[/(?<=\/groups\/)(\d+)/].to_i
  user_id = session[:user_id]

  # user can only kick itself
  if !(member_id == user_id || user_is_owner_of_group(group_id, user_id))
    redirect("/groups/#{group_id}?error=access-denied")
  end
end

before /(\/groups\/)\d+(\/(roles|members|edit|update|destroy))(\/(?!\d+\/destroy).*)?/ do
  group_id = request.path_info[/(?<=\/groups\/)(\d+)/]
  user_id = session[:user_id]

  if (group_id)
    # check if user is admin/creator
    if (!user_is_owner_of_group(group_id, user_id))
      redirect("/groups/#{group_id}?error=access-denied")
    end
  end
end

helpers do
  def groups(user_id = session[:user_id])
    return get_groups_of_user(user_id)
  end

  def members(group_id = params[:group_id])
    return get_members_in_group(group_id)
  end

  def role(role_id = params[:role_id])
    return get_role(role_id)
  end

  def group(group_id = params[:group_id])
    return get_group_by_id(group_id)
  end

  def current_user_can_kick(member_id, group_id)
    user_id = session[:user_id]
    return user_can_kick(user_id, member_id, group_id)
  end

  def user(user_id = session[:user_id])
    return get_user_by_id(user_id)
  end
end

# Display login page
#
get('/login') do
  slim(:login)
end

# Login a user with username and password by updating session
#
# @param [String] username, Username for authentication
# @param [String] password, Password for authentication
#
# @see Model#login_user
post('/login') do
  username = params[:username]
  password = params[:password]

  errors = login_user(username, password)

  if (session[:login_attempts].kind_of?(Array))
    # filter out old login attempts
    session[:login_attempts] = session[:login_attempts].select { |time| Time.now.to_i - time < 60 }
  else
    session[:login_attempts] = []
  end

  if (session[:login_attempts].length >= MAX_LOGIN_ATTEMPTS)
    redirect('/login?error=timeout')
  end

  if errors[:error]
    session[:login_attempts] = session[:login_attempts] << Time.now.to_i

    redirect('/login?error=invalid')
  else
    session[:login_attempts] = []
    redirect('/')
  end
end

# Display singup page
#
get('/signup') do
  slim(:signup)
end

# Log out user session
#
post('/logout') do
  session[:user_id] = nil
  redirect('/login')
end

# Create a new user and redirect to '/' and updates session if successful or '/signup' if errors occured
#
# @param [String] username, Username for authentication
# @param [String] password, Password for authentication
# @param [String] confirm_password, Password confirmation. Should equal password for successful request
#
# @see Model#register_user
post('/users') do
  username = params[:username]
  password = params[:password]
  confirm_password = params[:confirm_password]

  errors = register_user(username, password, confirm_password)

  if errors[:error]
    redirect_url = '/signup?'

    errors[:validation_errors].each do |error|
      error[:errors].each do |code|
        redirect_url += error[:param] + '=' + code + '&'
      end
    end

    redirect(redirect_url[0...-1])
  else
    redirect('/')
  end
end

# Log out user session
#
get('/') do
  slim(:"groups/index")
end

# Redirect to '/'
#
get('/groups') do
  redirect('/')
end

# Create a new chat group and redirect to '/'
#
# @param [String] group_name, The name of the chat group
#
# @see Model#create_group
post('/groups') do
  group_name = params[:name]
  color = params[:color]
  user_id = session[:user_id]

  create_group(user_id, group_name, color)

  redirect('/')
end

# Display chat group creation form
#
get('/groups/new') do
  slim(:"groups/new")
end

# Display a group by id
#
# @param [Integer] :group_id, The ID of the group
#
# @see Model#get_group_by_id
# @see Model#get_messages_in_group
get('/groups/:group_id') do
  group_id = params[:group_id]
  user_id = session[:user_id]

  if (!user_exists_in_group(group_id, user_id))
    return 'You are not a member of this group'
  end

  group = get_group_by_id(group_id)
  messages = get_messages_in_group(group_id)

  slim(:"groups/show", locals: { group: group, messages: messages })
end

# Display group edit form
#
get('/groups/:group_id/edit') do
  slim(:"groups/edit")
end

# Update a chat group and redidrect to '/groups/:group_id' or display error
#
# @param [Integer] :group_id, The ID of the group
# @param [String] title, The new name of the group
#
# @see Model#update_group
post('/groups/:group_id/update') do
  group_id = params[:group_id]
  color = params[:color]
  user_id = session[:user_id]
  title = params[:name]

  update_group(group_id, title, color)

  redirect("/groups/#{group_id}")
end

# Delete a chat group by id and redirect to '/groups'
#
# @param [Integer] :group_id, The ID of the group
#
# @see Model#delete_group
post('/groups/:group_id/destroy') do
  group_id = params[:group_id]
  user_id = session[:user_id]

  delete_group(group_id)

  redirect('/groups')
end

# Websocket connection route for live message feed
#
# @param [Integer] :group_id, The ID of the group
get('/groups/:group_id/messages') do
  if request.websocket?
    request.websocket do |ws|
      ws.onopen do
        settings.sockets << ws
      end
      ws.onclose do
        warn('websocket closed')
        settings.sockets.delete(ws)
      end
    end
  else
    return
  end
end

# Create a new message in a group and redirect to '/groups/:group_id' or display error
#
# @param [Integer] :group_id, The ID of the group
# @param [String] message, The text of the message
#
# @see Model#create_message_in_group
post('/groups/:group_id/messages') do
  group_id = params[:group_id]
  message = params[:message]
  user_id = session[:user_id]

  if (!user_exists_in_group(group_id, user_id))
    return 'You are not a member of this group'
  end

  msg = create_message_in_group(group_id, user_id, message)

  EM.next_tick {
    settings.sockets.each { |s|
      s.send(JSON.generate({
        id: msg['id'],
        username: msg['username'],
        msg: message
      }))
    }
  }

  redirect("/groups/#{group_id}")
end

# Update a message in a group
#
# @param [Integer] :group_id, The ID of the group
# @param [Integer] :message_id, The ID of the message
# @param [String] new_message, The new text of the message
#
# @see Model#update_message
post('/groups/{group_id}/messages/{message_id}/update') do
  group_id = params[:group_id]
  message_id = params[:message_id]
  new_message = params[:new_message]

  update_message(message_id, new_message)

  redirect("/groups/#{group_id}")
end

# Delete a message in a group and redirect to '/groups:group_id' or display error
#
# @param [Integer] :group_id, The ID of the group
# @param [Integer] :message_id, The ID of the message
#
# @see Model#delete_message
post('/groups/{group_id}/messages/:message_id/destroy') do
  group_id = params[:group_id]
  message_id = params[:message_id]
  user_id = session[:user_id]

  begin
    delete_message(group_id, message_id, user_id)
  rescue => e
    return e.message
  else
    EM.next_tick {
      settings.sockets.each { |s|
        s.send(JSON.generate({
          type: 'delete',
          id: message_id
        }))
      }
    }
  end

  redirect("/groups/#{group_id}")
end

# Add a member to a group and redirect to '/groups/:group_id/members/edit' or display error
#
# @param [Integer] :group_id, The ID of the group
# @param [String] new_member_username, The username of the member to add
#
# @see Model#add_member_to_group
post('/groups/:group_id/members') do
  new_member_username = params[:new_member_username]
  group_id = params[:group_id]
  user_id = session[:user_id]

  begin
    add_member_to_group(group_id, new_member_username)
  rescue => e
    return e.message
  end

  redirect("/groups/#{group_id}/members/edit")
end

# Display members editing form
#
# @param [Integer] :group_id, The ID of the group
get('/groups/:group_id/members/edit') do
  group_id = params[:group_id]
  user_id = session[:user_id]

  # check if user is owner of group
  group_roles = get_roles_in_group(group_id)

  slim(:"members/edit", locals: { group_roles: group_roles })
end

# Kick a member from a group and redirect to '/groups/:group_id/members/edit' or display error
#
# @param [Integer] :group_id, The ID of the group
# @param [Integer] :member_id, The ID of the member to kick
#
# @see Model#delete_member
post('/groups/{group_id}/members/{member_id}/destroy') do
  group_id = params[:group_id]
  member_id = params[:member_id]
  user_id = session[:user_id]

  delete_member(member_id, group_id)

  redirect_route = params[:redirect]
  if (redirect_route)
    redirect(redirect_route)
  else
    redirect("/groups/#{group_id}/members/edit")
  end
end

# Display all roles in a group
#
# @param [Integer] :group_id, The ID of the group
get('/groups/:group_id/roles') do
  group_id = params[:group_id]
  user_id = session[:user_id]

  roles = get_roles_in_group(group_id)

  slim(:"roles/index", locals: { roles: roles })
end

# Display form for creation of new roles in a group
#
# @param [Integer] :group_id, The ID of the group
get('/groups/:group_id/roles/new') do
  group_id = params[:group_id]
  user_id = session[:user_id]

  slim(:"roles/new")
end

# Create a new role in a group and redirect to '/groups/:group_id/roles'
#
# @param [Integer] :group_id, The ID of the group
# @param [String] title, The name of the role
# @param [Boolean] can_delete, Whether or not the role should allow message deletion
# @param [Boolean] can_kick, Whether or the role should allow kicking of members
#
# @see Model#create_role
post('/groups/:group_id/roles') do
  group_id = params[:group_id]
  user_id = session[:user_id]

  title = params[:title]
  can_delete = params[:can_delete]
  can_kick = params[:can_kick]

  create_role(group_id, title, can_delete, can_kick)

  redirect("/groups/#{group_id}/roles")
end

# Display a single role
#
# @param [Integer] :group_id, The ID of the group
# @param [Integer] :role_id, The ID of the role
get('/groups/:group_id/roles/:role_id') do
  group_id = params[:group_id]
  user_id = session[:user_id]

  slim(:"roles/show")
end

# Display role editing form
#
# @param [Integer] :group_id, The ID of the group
# @param [Integer] :role_id, The ID of the role
get('/groups/:group_id/roles/:role_id/edit') do
  group_id = params[:group_id]
  user_id = session[:user_id]

  slim(:"roles/edit")
end

# Update a role and redirect to '/groups/:group_id/roles'
#
# @param [Integer] :group_id, The ID of the group
# @param [Integer] :role_id, The ID of the role
# @param [String] title, The new name of the role
# @param [Boolean] can_delete, Whether or not the role should allow message deletion
# @param [Boolean] can_kick, Whether or the role should allow kicking of members
#
# @see Model#update_role
post('/groups/:group_id/roles/:role_id/update') do
  group_id = params[:group_id]
  user_id = session[:user_id]
  role_id = params[:role_id]

  title = params[:title]
  can_delete = params[:can_delete]
  can_kick = params[:can_kick]

  update_role(role_id, title, can_delete, can_kick)

  redirect("/groups/#{group_id}/roles")
end

# Delete a role and redirect to '/groups/:group_id/roles'
#
# @param [Integer] :group_id, The ID of the group
# @param [Integer] :role_id, The ID of the role
#
# @see Model#delete_role_in_group
post('/groups/:group_id/roles/:role_id/destroy') do
  # TODO: delete role and remove role from all users with the role
  role_id = params[:role_id]
  group_id = params[:group_id]
  user_id = session[:user_id]

  delete_role_in_group(group_id, role_id)

  redirect("/groups/#{group_id}/roles")
end

# Update a member's role and redirect to '/groups/:group_id/members/edit'
#
# @param [Integer] :group_id, The ID of the group
# @param [Integer] :user_id, The ID of the user
# @param [Integer] role_id, The ID of the role
#
# @see Model#update_role_of_user_in_group
post('/groups/:group_id/members/:user_id/role/update') do
  role_id = params[:role_id]
  group_id = params[:group_id]
  member_user_id = params[:user_id]

  user_id = session[:user_id]

  update_role_of_user_in_group(group_id, member_user_id, role_id)

  redirect("/groups/#{group_id}/members/edit")
end
