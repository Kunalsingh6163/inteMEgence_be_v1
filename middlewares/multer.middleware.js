const multer = require("multer")

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
      cb(null, "./public")
    },
    filename: function (req, file, cb) {
      cb(null, `${file.originalname}_${Date.now()}${path.extname(file.originalname)})`)
    }
  })
  
  const upload = multer({ 
    storage,
 })
