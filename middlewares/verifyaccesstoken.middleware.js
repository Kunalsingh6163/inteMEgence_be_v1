// Middleware to verify access token
const verifyAccessToken = (req, res, next) => {
    const accessToken = req.cookies.access_token;
  
    if (!accessToken) {
      return res.status(401).json({ message: "Access token not found" });
    }
  
    try {
      const decoded = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
      req.user = decoded;
      next();
    } catch (error) {
      return res.status(403).json({ message: "Invalid access token" });
    }
  };
