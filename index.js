const crypto = require('crypto');
const mysql = require('mysql');
const express = require('express');
const bodyParser = require('body-parser');
const uuid = require('uuid');
const { Server } = require('http');

const con = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'sigfood',
});

const genRandomString = function(length){
    return crypto.randomBytes(Math.ceil(length/2))
    .toString('hex')
    .slice(0,length);
};
var sha512 = function(password, salt){
    var hash = crypto.createHmac('sha512', salt)
    hash.update(password)
    var value = hash.digest('hex')
    return {
        salt: salt,
        passwordHash: value
    }
};

function saltHashPassword(userPassword){
    var salt = genRandomString(16);
    var passwordData = sha512(userPassword, salt);
    return passwordData;
}

function checkHashPassword(userPassword, salt) {
    var passwordData = sha512(userPassword, salt);
    return passwordData;
}


const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended:true}));

app.post('/signup', (req, res, next) => {
    var post_data = req.body;

    var uid = uuid.v4();
    var plain_password = post_data.password;
    var hash_data = saltHashPassword(plain_password);
    var password = hash_data.passwordHash;
    var salt = hash_data.salt;

    var name = post_data.name;
    var email = post_data.email;

    con.query('SELECT * FROM users where email=?', [email], function(err,result,fields){
        con.on('error', function(err){
            console.log(['MySQL Error'], err);
        });

        if(result && result.length){
            res.json('Pengguna sudah terdaftar!!');
        }
        else{
            con.query("INSERT INTO `users` (`unique_id`, `name`, `email`, `enc_password`, `salt`) VALUES (?,?,?,?,?)", [uid, name, email, password, salt], function(err, result, fields){
                con.on('error', function(err){
                    console.log(['MySQL Error'], err);
                    res.json('Daftar Gagal (', err, ')');
                });
                res.json('Daftar Berhasil');
            });
        };
    })
});

app.post('/login', (req, res, next) => {
    var post_data = req.body;

    var user_password = post_data.password;
    var email = post_data.email;

    con.query('SELECT * FROM users where email=?', [email], function(err,result,fields){
        con.on('error', function(err){
            console.log(['MySQL Error'], err);
        });

        if(result && result.length){
            var salt = result[0].salt;
            var encrypted_password = result[0].enc_password;

            var hashed_password = checkHashPassword(user_password, salt).passwordHash;

            //cek password
            if(encrypted_password == hashed_password){
                console.log("Berhasil Login");
                res.end(JSON.stringify(result[0]));
            } else {
                res.end(JSON.stringify('Salah email atau password'));
            }
        }
        else{
            res.json('Penngguna tidak ditemukan');
        };
    })
})
/*app.get('/', (req, res, next) => {
    console.log("Pass:123");
    var encrypt = saltHashPassword('123');
    console.log("encrypt: "+encrypt.passwordHash);
    console.log("salt: " +encrypt.salt);
})*/

app.listen(8080, () => {
    console.log('Server berjalan di 8080');
})
