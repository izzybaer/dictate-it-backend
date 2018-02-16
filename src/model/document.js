import mongoose from 'mongoose';
mongoose.Promise = Promise;

const documentSchema = new mongoose.Schema({
  ownerId: {type: mongoose.Schema.Types.ObjectId, required: true, ref: 'user'},
  title: {type: String, required: true},
  description: {type: String, required: true},
  body: {type: String},
});

export default mongoose.model('document', documentSchema);