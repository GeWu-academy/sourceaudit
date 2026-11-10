class UsersController < ApplicationController
  def update
    User.find(params[:id]).update(params.permit!)
  end
end
