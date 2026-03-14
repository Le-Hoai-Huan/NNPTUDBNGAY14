let express = require('express')
let router = express.Router()
let userController = require('../controllers/users')
let { RegisterValidator, ChangePasswordValidator, validatedResult } = require('../utils/validator')
let bcrypt = require('bcrypt')
let jwtHandler = require('../utils/jwtHandler')
const { checkLogin } = require('../utils/authHandler')

router.post('/register', RegisterValidator, validatedResult, async function (req, res, next) {
    try {
        let { username, password, email } = req.body;
        let newUser = await userController.CreateAnUser(
            username, password, email, '69b2763ce64fe93ca6985b56'
        )
        res.send(newUser)
    } catch (error) {
        if (error && error.code === 11000) {
            if (error.keyPattern && error.keyPattern.username) {
                res.status(409).send({
                    message: 'username da ton tai'
                })
                return;
            }
            if (error.keyPattern && error.keyPattern.email) {
                res.status(409).send({
                    message: 'email da ton tai'
                })
                return;
            }
            res.status(409).send({
                message: 'du lieu da ton tai'
            })
            return;
        }
        res.status(400).send({
            message: error.message
        })
    }
})
router.post('/login', async function (req, res, next) {
    let { username, password } = req.body;
    let user = await userController.FindUserByUsername(username);
    if (!user) {
        res.status(404).send({
            message: "thong tin dang nhap khong dung"
        })
        return;
    }
    if (!user.lockTime || user.lockTime < Date.now()) {
        if (bcrypt.compareSync(password, user.password)) {
            user.loginCount = 0;
            await user.save();
            let token = jwtHandler.signAccessToken({
                id: user._id,
            })
            res.send(token)
        } else {
            user.loginCount++;
            if (user.loginCount == 3) {
                user.loginCount = 0;
                user.lockTime = new Date(Date.now() + 60 * 60 * 1000)
            }
            await user.save();
            res.status(404).send({
                message: "thong tin dang nhap khong dung"
            })
        }
    } else {
        res.status(404).send({
            message: "user dang bi ban"
        })
    }

})
router.post('/change-password', checkLogin, ChangePasswordValidator, validatedResult, async function (req, res, next) {
    try {
        let { oldpassword, newpassword } = req.body;
        let user = req.user;

        if (!bcrypt.compareSync(oldpassword, user.password)) {
            res.status(404).send({
                message: "mat khau cu khong dung"
            })
            return;
        }

        user.password = newpassword;
        await user.save();
        res.send({
            message: "doi mat khau thanh cong"
        })
    } catch (error) {
        res.status(400).send({
            message: error.message
        })
    }
})
router.get('/me',checkLogin, function (req,res,next) {
    res.send(req.user)
})

module.exports = router;