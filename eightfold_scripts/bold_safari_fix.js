console.log('starting safari fix');
const ua = navigator.userAgent;
const isSafari = ua.includes("Safari") && !ua.includes("Chrome") && !ua.includes("Chromium");

console.log('User Agent:', ua);
console.log('isSafari:', isSafari);
console.log('body:', document.body);

if (isSafari && document.body) {
  document.body.classList.add("safari");
  console.log('✅ Added class "safari" to <body>');
} else {
  console.log('❌ Failed to add class');
}