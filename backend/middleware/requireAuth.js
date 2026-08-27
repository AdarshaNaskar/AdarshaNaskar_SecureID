const { SESSION_COOKIE_NAME, getSession } = require("../session");

async function requireAuth(req, res, next) {
  try {
    const cookieHeader = req.headers.cookie || "";

    let sessionToken = null;

    const cookies = cookieHeader.split(";");

    for (const cookie of cookies) {
      const [name, ...valueParts] = cookie.trim().split("=");

      if (name === SESSION_COOKIE_NAME) {
        sessionToken = decodeURIComponent(valueParts.join("="));

        break;
      }
    }

    if (!sessionToken) {
      return res.status(401).json({
        success: false,
        message: "Authentication required.",
      });
    }

    const session = await getSession(sessionToken);

    if (!session) {
      return res.status(401).json({
        success: false,
        message: "Your session is invalid or has expired.",
      });
    }

    /*
     * Make the authenticated user
     * available to the route.
     */

    req.user = {
      id: session.user_id,
      email: session.email,
      fullName: session.full_name,
    };

    req.sessionInfo = session;

    next();
  } catch (error) {
    console.error("Authentication middleware error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to verify your session.",
    });
  }
}

module.exports = {
  requireAuth,
};
