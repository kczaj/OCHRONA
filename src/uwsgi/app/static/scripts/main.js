document.addEventListener("DOMContentLoaded", (e) => {
    let loginForm = document.getElementById("loginBtn")
    let registerForm = document.getElementById("registerBtn")
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

    loginForm.addEventListener("click", (e) => {
        console.log("login")
        let usernameInput = document.getElementById("inputUsernameS")
        let passwordInput = document.getElementById("inputPasswordS")
        if (usernameInput.value !== "" && passwordInput.value !== "") {
            let username = usernameInput.value
            let password = usernameInput.value

            if (validateFieldsLogin(username, password)) {
                console.log("wyqgh")
            } else {
                alertLogin.style.display = "block"
                setTimeout(() => {
                    console.log("World!");
                }, 5000);
            }
        }
    })

    function validateFieldsRegister(name, surname, username, email, password) {
        if (!/^[a-zA-Z0-9]+$/.test(username)) {
            return false;
        }
        if (!/^[a-zA-Z]+$/.test(name)) {
            return false;
        }
        if (!/^[a-zA-Z]+$/.test(surname)) {
            return false;
        }
        if (!/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}$/.test(email)) {
            return false;
        }
        if (password.length > 8 && !/^[a-zA-Z0-9!@#$%&*]+$/.test(password)) {
            return false;
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
            let pi = value/password.length
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
        } else if(entropy > 3) {
            progresBar.style.width = "40%"
            progresBar.className = "progress-bar bg-warning"
        } else{
            progresBar.style.width = "10%"
            progresBar.className = "progress-bar bg-danger"
        }
    })

    registerForm.addEventListener("click", (e) => {
        console.log("regiser")
        let usernameInput = document.getElementById("inputUsernameR")
        let emailInput = document.getElementById("inputEmailR")
        let nameInput = document.getElementById("inputNameR")
        let surnameInput = document.getElementById("inputSurnameR")

        if (usernameInput.value !== "" && passwordInput.value !== "" && emailInput.value !== "" && nameInput !== "" && surnameInput !== "") {
            let name = nameInput.value
            let surname = surnameInput.value
            let username = usernameInput.value
            let email = emailInput.value
            let password = passwordInput.value

            if (validateFieldsRegister(name, surname, username, email, password)) {
                console.log("register")
            } else {
                console.log("not register")
            }
        }
    })
})