const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  passwordHash: String
});

module.exports = mongoose.model('User', UserSchema);
