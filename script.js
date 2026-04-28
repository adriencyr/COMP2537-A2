const logged_in = false;
const name = "Adrien";

if (logged_in) {
    document.querySelector('body').innerHTML = `
        <p>Hello, ${name}!</p>
        <input type="button" onclick="window.location.href='/signup'" id="btn-signup" value="Go to Members Area">
        <input type="button" onclick="window.location.href='/login'" id="btn-login" value="Logout">
    `
} else {
    document.querySelector('body').innerHTML = `
        <input type="button" onclick="window.location.href='/signup'" id="btn-signup" value="Sign up">
        <input type="button" onclick="window.location.href='/login'" id="btn-login" value="Log in">
    `
}