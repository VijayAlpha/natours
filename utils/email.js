const nodemailer = require('nodemailer');

const sendMail = async (options) => {
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    auth: {
      user: process.env.EMAIL_USERNAME,
      pass: process.env.EMAIL_PASSWORD,
    },
  });
  console.log('mail  passs 1');
  const info = {
    from: '"Vijay Murugan" <vijay@alpha.com>', // sender address
    to: options.email, // list of receivers
    subject: options.subject, // Subject line
    text: options.message, // plain text body
    // html: '<b>Hello world?</b>', // html body
  };
  console.log('mail pass 2');
  await transporter.sendMail(info);
  console.log('mail pass 3');
};

module.exports = sendMail;
