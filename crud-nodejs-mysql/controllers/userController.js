const db = require('../db/connection'); 
const bcrypt = require('bcrypt');
// CREATE 
exports.createUser = (req, res) => { 
 const { nome_usuario, email_usuario, senha_usuario } = req.body; 

 bcrypt.hash(senha_usuario, 10, (error, novasenha) => {
    if (error) {
        return res.status(500).send({ msg: "Erro ao tentar cadastrar, tente novamente" });
    } else {
        // Atualizando a senha criptografada no body
        req.body.senha_usuario = novasenha;

 const sql = 'INSERT INTO usuarios (nome_usuario, email_usuario, senha_usuario) VALUES (?, ?,?)'; 
 db.query(sql, [nome_usuario, email_usuario, req.body.senha_usuario], (err, result) => { 
 if (err) return res.status(500).send(err); 
 res.status(201).json({ id: result.insertId, nome_usuario, email_usuario }); 
 }); 
}; 
});
};

// READ 
exports.getUsers = (req, res) => { 
 db.query('SELECT nome_usuario, email_usuario FROM usuarios', (err, results) => { 
 if (err) return res.status(500).send(err); 
 res.json(results); 
 }); 
}; 
// UPDATE 
exports.updateUser = (req, res) => { 
 const { id } = req.params; 
 const { nome_usuario, email_usuario, senha_usuario } = req.body; 
 const sql = 'UPDATE usuarios SET nome_usuario = ?, email_usuario = ? WHERE id = ?'; 
 db.query(sql, [nome_usuario, email_usuario, id], (err) => { 
 if (err) return res.status(500).send(err); 
 res.json({ id, nome_usuario, email_usuario }); 
 }); 
}; 
// DELETE 
exports.deleteUser = (req, res) => { 
 const { id } = req.params; 
 const sql = 'DELETE FROM usuarios WHERE id = ?'; 
 db.query(sql, [id], (err) => { 
 if (err) return res.status(500).send(err); 
 res.json({ message: `Usuário com ID ${id} deletado` }); 
 }); 
};


// LOGIN
exports.loginUser = (req, res) => {
    const { nome_usuario, senha_usuario } = req.body;

    db.query("SELECT * FROM usuarios WHERE nome_usuario = ?", [nome_usuario], (error, result) => {
        if (error) {
            return res.status(500).send({ msg: `Erro ao tentar logar: ${error}` });
        } else if (result[0] == null) {
            return res.status(400).send({ msg: "Usuário ou senha não existem" });
        } else {
            bcrypt.compare(senha_usuario, result[0].senha_usuario).then((igual) => {
                if (!igual) {
                    return res.status(400).send({ msg: "Usuário ou senha inválidos" });
                } else {
                    return res.status(200).send({ msg: "Usuário logado com sucesso!" });
                }
            }).catch((error) => res.status(500).send({ msg: `Erro ao verificar senha: ${error}` }));
        }
    });
};