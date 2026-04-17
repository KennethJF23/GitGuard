const axios = require("axios");

async function verifyCaptcha(req, res, next) {
  const captchaSecret = process.env.RECAPTCHA_SECRET_KEY?.trim();
  const isProd = process.env.NODE_ENV === "production";

  if (!captchaSecret) {
    return res.status(500).json({
      message:
        "CAPTCHA is not configured on the server (missing RECAPTCHA_SECRET_KEY in server/.env).",
    });
  }

  const captchaToken = req.body?.captchaToken;
  if (!captchaToken || typeof captchaToken !== "string") {
    return res.status(400).json({
      message: "CAPTCHA verification is required.",
    });
  }

  try {
    const params = new URLSearchParams({
      secret: captchaSecret,
      response: captchaToken,
    });

    const { data } = await axios.post(
      "https://www.google.com/recaptcha/api/siteverify",
      params.toString(),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        timeout: 5000,
      },
    );

    // Helpful for debugging in local dev; avoid logging tokens/secrets.
    if (!isProd) {
      console.log("CAPTCHA verify response:", {
        success: data?.success,
        hostname: data?.hostname,
        challenge_ts: data?.challenge_ts,
        errorCodes: data?.["error-codes"],
      });
    }

    if (!data?.success) {
      const errorCodes = Array.isArray(data?.["error-codes"])
        ? data["error-codes"]
        : [];

      return res.status(400).json(
        isProd
          ? { message: "CAPTCHA verification failed. Please try again." }
          : {
              message: "CAPTCHA verification failed.",
              details: {
                errorCodes,
                hostname: data?.hostname,
              },
            },
      );
    }

    return next();
  } catch (error) {
    const isTimeout = error?.code === "ECONNABORTED";

    console.error("CAPTCHA verify error:", {
      message: error?.message,
      code: error?.code,
      responseStatus: error?.response?.status,
    });

    if (isTimeout) {
      return res.status(504).json({
        message: "CAPTCHA verification timed out. Please try again.",
      });
    }

    return res.status(502).json({
      message: "Unable to verify CAPTCHA at the moment. Please retry.",
    });
  }
}

module.exports = verifyCaptcha;
