db = db.getSiblingDB('auth');

db.users.createIndex({ "username": 1 }, { unique: true });

db.users.insertOne({
  username: "admin",
  password: "$2a$10$oPo4x7lLEK7Laq9JiRvNZuWfKekqSF7A.j5HPJPeK5oYJCu9Xd5Hu",
  role: "admin",
  createdAt: new Date()
});

db.users.insertOne({
  username: "user",
  password: "$2a$10$AJ5jmVrvW0JA.Ocfg2ZJseX/2qCxx2eMr0nYuZ/F2IYxheBCCLR/O",
  role: "user",
  createdAt: new Date()
});

