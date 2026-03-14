let userController = require("../controllers/users")
let jwtHandler = require('./jwtHandler')
module.exports = {
    checkLogin: async function (req, res, next) {
        try {
            let token = req.headers.authorization;
            if (!token || !token.startsWith('Bearer ')) {
                res.status(404).send("ban chua dang nhap")
                return;
            }
            token = token.split(" ")[1];
            let result = jwtHandler.verifyAccessToken(token);
            let user = await userController.FindUserById(result.id);
            if (user) {
                req.user = user
                next()
            } else {
                res.status(404).send("ban chua dang nhap")
            }
        } catch (error) {
            res.status(404).send("ban chua dang nhap")
        }
    }
}