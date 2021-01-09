document.addEventListener("DOMContentLoaded", (e) => {
    let baseURL = "https://localhost/"
    let loginBtn = document.getElementById("loginBtn")
    let registerBtn = document.getElementById("registerBtn")
    let alertRegister = document.getElementById("alertRegister")
    let alertLogin = document.getElementById("alertLogin")
    let progresBar = document.getElementById("progressbar")
    let passwordInput = document.getElementById("inputPasswordR")
    progresBar.style.width = "0%"
    alertRegister.style.display = "none"
    alertLogin.style.display = "none"

    function validateFieldsLogin(username, password) {
        if (!/^[a-zA-Z0-9]+$/.test(username)) {
            return false;
        }
        if (!/^[a-zA-Z0-9!@#$%&*]+$/.test(password)) {
            return false;
        }
        return true;
    }

    loginBtn.addEventListener("click", async (e) => {
        e.preventDefault();
        let usernameInput = document.getElementById("inputUsernameS")
        let passwordInput = document.getElementById("inputPasswordS")
        if (usernameInput.value !== "" && passwordInput.value !== "") {
            let username = usernameInput.value
            let password = usernameInput.value

            if (validateFieldsLogin(username, password)) {
                let loginForm = document.getElementById("login-form")
                let formData = new FormData(loginForm)
                let result = await loginUser(formData)
                if (result === 200) {
                    window.location.href = "user/"
                } else {
                    alertLogin.style.display = "block"
                }
            } else {
                alertLogin.style.display = "block"
            }
        }
    })

    function validateFieldsRegister(name, surname, username, email, password) {
        if (!/^[a-zA-Z0-9]+$/.test(username)) {
            console.log("username");
            throw "Wrong username format"
        }
        if (!/^[a-zA-Z]+$/.test(name)) {
            console.log("name");
            throw "Wrong name format"
        }
        if (!/^[a-zA-Z]+$/.test(surname)) {
            console.log("surname");
            throw "Wrong surname format"
        }
        if (!/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}$/.test(email)) {
            console.log("email");
            throw "Wrong email format"
        }
        if (password.length > 8 && !/^[a-zA-Z0-9!@#$%&*]+$/.test(password)) {
            throw "Wrong password format"
        }
        return true;
    }

    function calculateEntropy(password) {
        let stat = {}
        for (let c of password) {
            if (c in stat) {
                stat[c] += 1
            } else {
                stat[c] = 1
            }
        }
        let H = 0.0
        Object.entries(stat).forEach(([key, value]) => {
            let pi = value / password.length
            H -= pi * Math.log2(pi)
        })
        return H
    }

    passwordInput.addEventListener("change", (e) => {
        let password = passwordInput.value
        let entropy = calculateEntropy(password)
        if (entropy > 4) {
            progresBar.style.width = "100%"
            progresBar.className = "progress-bar bg-success"
        } else if (entropy > 3) {
            progresBar.style.width = "40%"
            progresBar.className = "progress-bar bg-warning"
        } else if (password === "") {
            progresBar.style.width = "0%"
        } else {
            progresBar.style.width = "10%"
            progresBar.className = "progress-bar bg-danger"
        }
    })

    registerBtn.addEventListener("click", async (e) => {
        e.preventDefault()
        let usernameInput = document.getElementById("inputUsernameR")
        let emailInput = document.getElementById("inputEmailR")
        let nameInput = document.getElementById("inputNameR")
        let surnameInput = document.getElementById("inputSurnameR")

        if (usernameInput.value !== "" && passwordInput.value !== "" && emailInput.value !== "" && nameInput.value !== "" && surnameInput.value !== "") {
            let name = nameInput.value;
            let surname = surnameInput.value;
            let username = usernameInput.value;
            let email = emailInput.value;
            let password = passwordInput.value;

            try {
                // if (calculateEntropy(password) < 4) {
                //     throw "You need to create harder password"
                // }
                if (validateFieldsRegister(name, surname, username, email, password)) {
                    let registerForm = document.getElementById("register-form")
                    let formData = new FormData(registerForm)
                    let result = await registerUser(formData)
                    if (result === 200) {
                        window.location.href = "user/"
                    } else {
                        let getSpan = document.getElementById("alertR")
                        if (getSpan !== null) {
                            alertRegister.removeChild(getSpan)
                        }
                        let span = document.createElement("span")
                        span.setAttribute("id", "alertR")
                        let text = document.createTextNode("Something went wrong.")
                        span.appendChild(text)
                        alertRegister.appendChild(span)
                        alertRegister.style.display = "block"
                    }
                }
            } catch (error) {
                let getSpan = document.getElementById("alertR")
                if (getSpan !== null) {
                    alertRegister.removeChild(getSpan)
                }
                let span = document.createElement("span")
                span.setAttribute("id", "alertR")
                let text = document.createTextNode(error)
                span.appendChild(text)
                alertRegister.appendChild(span)
                alertRegister.style.display = "block"
            }
        }
    });

    async function registerUser(formData) {
        let requestURL = baseURL + "register/"
        let requestParam = {
            method: "POST",
            body: formData,
            redirect: "follow",
        };

        let res = await fetch(requestURL, requestParam)
        return res.status
    }

    async function loginUser(formData) {
        let requestURL = baseURL + "login/"
        let requestParam = {
            method: "POST",
            body: formData,
            redirect: "follow",
        };

        let res = await fetch(requestURL, requestParam)
        return res.status
    }

})