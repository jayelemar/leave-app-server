import nodemailer, { TransportOptions } from 'nodemailer'
import hbs from 'nodemailer-express-handlebars'
import path from 'path'

export const sendAutoEmail = async (
  subject: string,
  send_to: string,
  sent_from: string,
  reply_to: string,
  template: string,
  name: string,
  link: string,
) => {
  // create transporter
  const transporter = nodemailer.createTransport({
    host: process.env.AWS_SMTP_HOST,
    port: 587,
    secure: false, // true for 465, false for other ports
    auth: {
      user: process.env.AWS_SMTP_USERNAME,
      pass: process.env.AWS_SMTP_PASSWORD,
    },
  } as TransportOptions)

  // Define handlebarOptions with the custom type
  const viewsPath = path.join(__dirname, '..', 'views')
  const handlebarOptions = {
    viewEngine: {
      extName: '.handlebars',
      partialsDir: viewsPath,
      layoutsDir: undefined,
      defaultLayout: undefined,
    },
    viewPath: viewsPath, // Use the absolute path here
    extName: '.handlebars',
  }

  transporter.use('compile', hbs(handlebarOptions as any))

  // Options for sending email
  const mailOptions = {
    from: sent_from,
    to: send_to,
    replyTo: reply_to,
    subject,
    template,
    context: {
      name,
      link,
    },
  }

  // Send the email
  transporter.sendMail(mailOptions, (error: any, info: any) => {
    if (error) {
      console.log('Error:', error)
    } else {
      console.log('Email sent:', info.response)
    }
  })
}
