import Mailgen from "mailgen";



const emailVerificationMailgenContent = ( 
  username, verificationUrl) => {
  return {
    body: {
      name: username,
      intro: "Welcome to our App! we're Excited to have you on board.",
      action: {
        instructions:
          "To verify your email please click on the following button",
        button: {
          color: "#1b4295ff",
          text: "Verify your email",
          link: verificationUrl,
        },
      },
      outro:
        "Need help, or have questions? Just reply to this email,we'd love to help",
    },
  };
}


const forhotpasswordMailgenContent = ( 
  username, passwordresetUrl) => {
  return {
    body: {
      name: username,
      intro: "We got a request to reset the password of your account.",
      action: {
        instructions: "To reset your password please click on the following button or link",
        button: {
          color: "#1b4295ff",
          text: "Reset Password",
          link: passwordresetUrl
        },
      },
      outro: "Need help, or have questions? Just reply to this email,we'd love to help",
    },
  };
}

export {
  emailVerificationMailgenContent,
  forhotpasswordMailgenContent
}