const mongoose = require ('mongoose');

const otpSchema = new mongoose.Schema({
    email:{
        type: String,
        required :true
    },
    otp:{
        type: String,
        required: true
    },
action:{
    type: String,
    enum:['account_verification','event_booking'
    ],
    required:true
},
createdAt:{
    type:Date,
    default:Date.now,
    expires: 300 //otp expires after 5 min
}
});

module.exports = mongoose.model('OTP', otpSchema);