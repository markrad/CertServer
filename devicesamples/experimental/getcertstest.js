let { getCerts, getTrust } = require('./getcerts');

const server = 'http://mrubu2204dt.lan:4141';
getCerts(server, 24, 23)
.then((data) => {
    console.log('Certificate chain and key');
    console.log(data.cert);
    console.log(data.key);    
},
(err) => console.log(`getCerts failed with ${err}`)
);

getTrust(server, 1)
.then((data) => {
    console.log('Root certificate');
    console.log(data);
},
(err) => console.log(`getTrust failed with ${err}`)
);
