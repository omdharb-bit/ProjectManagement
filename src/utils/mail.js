import { text } from "express";
import Mailgen from "mailgen";
import nodemailer from "nodemailer";

const sendEmail = async (options) => {
  const mailGenerator = new Mailgen({
    theme: "default",
    product: {
      name: "Task Manager",
      link: "https://taskmanagerlink.com"
    }
  })
  
  const emailTextual = mailGenerator.generatePlaintext(options.mailegenContent)
  
 const emailHtml= mailGenerator.generate(options.mailegenContent)
  
  
const transporter=  nodemailer.createTransport({
    host: process.env.MAILTRAP_SMTP_HOST, 
 port:  process.env.MAILTRAP_SMTP_PORT, 
    auth: {
      user: process.env.MAILTRAP_SMTP_USER,
      pass: process.env.MAILTRAP_SMTP_PASS
    }
    
})
  
  const mail = {
    from: "mail-taskmanager@example.com",
    to: options.email,
    subject: options.subject,
    text: emailTextual,
    html: emailHtml
  }
  
  try {
  await transporter.sendMail(mail)
  } catch (error) {
  console.error("Email service failed silently. Make sure that you have proovided your MAILTRAP credentials in the .env file")
console.error ("Error:",error)
  }
}


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
  forhotpasswordMailgenContent,sendEmail
}