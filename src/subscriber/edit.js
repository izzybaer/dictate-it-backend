import Document from '../model/document.js';

const EDIT = socket => payload => {
  let referrer = socket.handshake.headers.referer.split('/')[4];
  console.log('__REFERRER__', referrer);
  console.log('__PAYLOAD_ID__', payload._id);
  if(referrer.length > 0 && payload._id.toString() === referrer.toString())
    Document.findByIdAndUpdate(payload._id, payload, {new: true, runValidators: true})
      .then(document => {
        socket.broadcast.emit('__EDIT__', document._document)
      });
};

export default {EDIT};