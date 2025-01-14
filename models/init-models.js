var DataTypes = require("sequelize").DataTypes;
var _refresh_tokens = require("./refresh_tokens");
var _users = require("./users");

function initModels(sequelize) {
  var refresh_tokens = _refresh_tokens(sequelize, DataTypes);
  var users = _users(sequelize, DataTypes);

  refresh_tokens.belongsTo(users, { as: "email_user", foreignKey: "email"});
  users.hasMany(refresh_tokens, { as: "refresh_tokens", foreignKey: "email"});

  return {
    refresh_tokens,
    users,
  };
}
module.exports = initModels;
module.exports.initModels = initModels;
module.exports.default = initModels;
