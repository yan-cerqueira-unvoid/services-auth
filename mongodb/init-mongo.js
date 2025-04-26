db = db.getSiblingDB('auth');

// Criar índice único no username para evitar duplicações
db.users.createIndex({ "username": 1 }, { unique: true });

// Inserir um usuário admin padrão
db.users.insertOne({
  username: "admin",
  // senha hash de "admin123"
  password: "$2a$10$oPo4x7lLEK7Laq9JiRvNZuWfKekqSF7A.j5HPJPeK5oYJCu9Xd5Hu",
  role: "admin",
  createdAt: new Date()
});

// Inserir um usuário comum para testes
db.users.insertOne({
  username: "user",
  // senha hash de "user123"
  password: "$2a$10$AJ5jmVrvW0JA.Ocfg2ZJseX/2qCxx2eMr0nYuZ/F2IYxheBCCLR/O",
  role: "user",
  createdAt: new Date()
});

print("MongoDB inicializado com sucesso com dados de teste!");
