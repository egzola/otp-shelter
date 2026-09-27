
/* ==========================================================
   SELECTOR
========================================================== */

const $ =
    selector =>
        document.querySelector(selector);


/* ==========================================================
   STATE
========================================================== */

let sites = [];

let refreshInProgress = false;

let toastTimer;

let codesHidden =
    localStorage.getItem("otpShelterCodesHidden") === "true";

let authenticated = false;
let vaultExists = false;

/* Auto logout after 15 minutes without user activity. */
const INACTIVITY_TIMEOUT = 15 * 60 * 1000;
let inactivityTimer = null;

function clearInactivityTimer() {
    if (inactivityTimer) {
        clearTimeout(inactivityTimer);
        inactivityTimer = null;
    }
}

async function performAutoLogout() {
    if (!authenticated) return;

    clearInactivityTimer();

    try {
        await fetch("/api/logout", {
            method: "POST",
            credentials: "same-origin"
        });
    } catch {
        // Local UI must still lock even if the request fails.
    }

    sites = [];
    render();
    setAuthenticatedUI(false);
    configureAuthScreen(true);
    $("#authPassword").value = "";
    showToast("Logged out due to inactivity.", "error");
}

function resetInactivityTimer() {
    if (!authenticated) return;
    clearInactivityTimer();
    inactivityTimer = setTimeout(performAutoLogout, INACTIVITY_TIMEOUT);
}

["pointerdown", "keydown", "touchstart"].forEach(eventName => {
    document.addEventListener(eventName, resetInactivityTimer, { passive: true });
});


/* ==========================================================
   API
========================================================== */

async function request(
    url,
    options = {}
) {

    const response =

        await fetch(
            url,
            { credentials: "same-origin", ...options }
        );


    const data =

        await response
            .json()
            .catch(() => ({}));


    if (!response.ok) {

        if (response.status === 401 && authenticated) {
            authenticated = false;
            sites = [];
            setAuthenticatedUI(false);
            configureAuthScreen(true);
        }

        throw new Error(

            data.error ||
            "Request failed."

        );

    }


    return data;

}


/* ==========================================================
   ESCAPE HTML
========================================================== */

function escapeHtml(
    value = ""
) {

    const div =
        document.createElement("div");


    div.textContent =
        value;


    return div.innerHTML;

}


/* ==========================================================
   TOAST
========================================================== */

function showToast(
    message,
    type = "success"
) {

    const toast =
        $("#toast");


    toast.innerHTML =

        `${type === "success"
            ? "✓"
            : "⚠"
        }
        <span>${escapeHtml(message)}</span>`;


    toast.style.borderColor =

        type === "success"

            ?

            "rgba(78,226,154,.38)"

            :

            "rgba(255,104,114,.38)";


    toast.classList.add(
        "show"
    );


    clearTimeout(
        toastTimer
    );


    toastTimer =

        setTimeout(

            () => {

                toast.classList.remove(
                    "show"
                );

            },

            2200

        );

}


/* ==========================================================
   MENU
========================================================== */

$("#menuButton").onclick =
    event => {

        event.stopPropagation();


        const panel =
            $("#menuPanel");


        const isOpen =

            panel.classList.toggle(
                "open"
            );


        $("#menuButton")
            .setAttribute(

                "aria-expanded",

                isOpen

            );

    };


document.addEventListener(

    "click",

    event => {

        const menu =
            $(".menu");


        if (
            !menu.contains(event.target)
        ) {

            $("#menuPanel")
                .classList.remove(
                    "open"
                );


            $("#menuButton")
                .setAttribute(
                    "aria-expanded",
                    "false"
                );

        }

    }

);


/* ==========================================================
   AUTHENTICATION
========================================================== */

function setAuthenticatedUI(isAuthenticated) {
    authenticated = isAuthenticated;
    document.body.classList.toggle("locked", !isAuthenticated);
    $("#authScreen").classList.toggle("hidden", isAuthenticated);
    $("#logoutButton").classList.toggle("hidden", !isAuthenticated);
    $("#menuButton").classList.toggle("hidden", !isAuthenticated);

    if (isAuthenticated) resetInactivityTimer();
    else clearInactivityTimer();
}

function configureAuthScreen(exists) {
    vaultExists = exists;
    $("#authTitle").textContent = exists ? "Unlock OTP-Shelter" : "Create your master password";
    $("#authDescription").textContent = exists
        ? "Enter your master password to unlock your encrypted vault."
        : "Choose a strong master password. It is never stored and cannot be recovered.";
    $("#authConfirmWrap").classList.toggle("hidden", exists);
    $("#authPassword").setAttribute("autocomplete", exists ? "current-password" : "new-password");
    $("#authSubmit").textContent = exists ? "Unlock vault" : "Create encrypted vault";
    $("#authWarning").classList.toggle("hidden", exists);
    $("#authHint").textContent = exists
        ? "Your password is never stored by OTP-Shelter."
        : "Minimum 9 characters.";
    $("#authPassword").focus();
}

async function checkStatus() {
    const status = await request("/api/status");
    configureAuthScreen(status.vaultExists);
    setAuthenticatedUI(Boolean(status.authenticated));
    if (status.authenticated) await load();
}

$("#authForm").addEventListener("submit", async event => {
    event.preventDefault();
    const password = $("#authPassword").value;
    const confirmPassword = $("#authConfirm").value;
    if (!vaultExists && password !== confirmPassword) {
        showToast("Passwords do not match.", "error");
        return;
    }
    const button = $("#authSubmit");
    const passwordInput = $("#authPassword");
    const confirmInput = $("#authConfirm");
    button.disabled = true;
    try {
        await request(vaultExists ? "/api/login" : "/api/setup", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ password })
        });
        $("#authForm").reset();
        setAuthenticatedUI(true);
        await load();
        showToast(vaultExists ? "Vault unlocked." : "Encrypted vault created.");
        vaultExists = true;
    } catch (error) {
        showToast(error.message, "error");

        // Brief cooldown after a failed password attempt.
        // This improves UX feedback and slows rapid retries.
        passwordInput.value = "";
        passwordInput.disabled = true;
        confirmInput.disabled = true;
        button.disabled = true;

        let remaining = 3;
        const originalText = vaultExists ? "Unlock vault" : "Create encrypted vault";
        button.textContent = `Try again in ${remaining}s`;

        const cooldown = setInterval(() => {
            remaining--;
            if (remaining > 0) {
                button.textContent = `Try again in ${remaining}s`;
            } else {
                clearInterval(cooldown);
                passwordInput.disabled = false;
                confirmInput.disabled = false;
                button.disabled = false;
                button.textContent = originalText;
                passwordInput.focus();
            }
        }, 1000);

        return;
    }

    button.disabled = false;
});

$("#logoutButton").onclick = async () => {
    clearInactivityTimer();
    try {
        await request("/api/logout", { method: "POST" });
    } finally {
        sites = [];
        render();
        setAuthenticatedUI(false);
        configureAuthScreen(true);
        $("#authPassword").value = "";
    }
};

/* ==========================================================
   CHANGE PASSWORD
========================================================== */

function openChangePasswordModal() {
    $("#menuPanel").classList.remove("open");
    $("#changePasswordForm").reset();
    $("#changePasswordModal").classList.add("open");
    document.body.style.overflow = "hidden";
    setTimeout(() => $("#currentPassword").focus(), 50);
}

function closeChangePasswordModal() {
    $("#changePasswordModal").classList.remove("open");
    document.body.style.overflow = "";
    $("#changePasswordForm").reset();
}

$("#changePasswordButton").onclick = openChangePasswordModal;
$("#closeChangePasswordModal").onclick = closeChangePasswordModal;
$("#cancelChangePassword").onclick = closeChangePasswordModal;
$("#changePasswordModal").onclick = event => {
    if (event.target === $("#changePasswordModal")) closeChangePasswordModal();
};

$("#changePasswordForm").addEventListener("submit", async event => {
    event.preventDefault();
    const currentPassword = $("#currentPassword").value;
    const newPassword = $("#newPassword").value;
    const confirmNewPassword = $("#confirmNewPassword").value;
    if (newPassword !== confirmNewPassword) {
        showToast("New passwords do not match.", "error");
        return;
    }
    const button = $("#saveChangePassword");
    button.disabled = true;
    try {
        await request("/api/change-password", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ currentPassword, newPassword })
        });
        closeChangePasswordModal();
        showToast("Master password changed successfully.");
    } catch (error) {
        $("#currentPassword").value = "";
        showToast(error.message, "error");
        $("#currentPassword").focus();
    } finally {
        button.disabled = false;
    }
});

/* ==========================================================
   LOAD
========================================================== */

async function load() {

    sites =

        await request(
            "/api/sites"
        );


    sites.sort((a, b) =>
        a.name.localeCompare(
            b.name,
            undefined,
            { sensitivity: "base" }
        )
    );

    render();


    await refreshCodes();

}


/* ==========================================================
   RENDER
========================================================== */

function render() {

    const query =

        $("#search")
            .value
            .toLowerCase()
            .trim();


    const filtered =

        sites.filter(

            site =>

                `${site.name}
             ${site.account || ""}
             ${site.issuer || ""}`

                    .toLowerCase()
                    .includes(query)

        );


    $("#count").textContent =

        `Accounts (${sites.length})`;


    $("#sites").innerHTML =

        filtered.length

            ?

            filtered

                .map(

                    site => `

<div
  class="site"
  data-id="${site.id}"
>

  <div class="siteInfo">

    <div
      class="siteName"
      data-edit="${site.id}"
      title="Click or tap to edit account name"
      role="button"
      tabindex="0"
      aria-label="Edit account name: ${escapeHtml(site.name)}"
    >
      ${escapeHtml(site.name)}
    </div>

    ${site.account

                            ?

                            `
        <div class="siteAccount">
          ${escapeHtml(site.account)}
        </div>
        `

                            :

                            ""
                        }

  </div>


  <div class="codeActions">


    <div
      class="code"
      data-code="${site.id}"
      title="Click to copy code"
      role="button"
      tabindex="0"
    >
      ••• •••
    </div>


    <button
      class="iconButton"
      data-copy="${site.id}"
      title="Copy code"
      aria-label="Copy code"
      ${codesHidden ? "disabled" : ""}
    >
      ⧉
    </button>



    <button
      class="iconButton dangerButton"
      data-delete="${site.id}"
      title="Delete ${escapeHtml(site.name)}"
      aria-label="Delete account"
    >
      🗑
    </button>


    <div
      class="otpTimer"
      data-timer="${site.id}"
      title="Loading..."
    >

      <span>
        --
      </span>

    </div>


  </div>

</div>

`

                )

                .join("")

            :

            `

<div class="empty">

  <div>

    <div class="emptyIcon">
      🔐
    </div>


    <h3>

      ${sites.length

                ?

                "No accounts found"

                :

                "Your shelter is empty"

            }

    </h3>


    <p>

      ${sites.length

                ?

                "Try changing your search."

                :

                "Add your first TOTP account to get started."

            }

    </p>


    ${sites.length

                ?

                ""

                :

                `

<button
  class="primary"
  type="button"
  onclick="openAddModal()"
>
  ＋ Add account
</button>

`

            }

  </div>

</div>

`;


    document

        .querySelectorAll(
            "[data-edit]"
        )

        .forEach(

            button => {

                button.onclick =
                    () =>

                        openEditModal(
                            button.dataset.edit
                        );

                button.onkeydown =
                    event => {

                        if (
                            event.key === "Enter" ||
                            event.key === " "
                        ) {

                            event.preventDefault();

                            openEditModal(
                                button.dataset.edit
                            );

                        }

                    };

            }

        );


    document

        .querySelectorAll(
            "[data-delete]"
        )

        .forEach(

            button => {

                button.onclick =
                    () =>

                        removeSite(
                            button.dataset.delete
                        );

            }

        );


    document

        .querySelectorAll(
            "[data-copy]"
        )

        .forEach(

            button => {

                button.onclick =
                    () =>

                        copyCode(
                            button.dataset.copy
                        );

            }

        );

}


/* ==========================================================
   HIDE / SHOW OTP CODES
========================================================== */

function setToggleCodesIcon(hidden) {

    const toggleIcon =
        $("#toggleCodesIcon");


    if (!toggleIcon) {
        return;
    }


    toggleIcon.innerHTML =
        hidden

            ?

            `
          <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"/>
            <circle cx="12" cy="12" r="2.5"/>
          </svg>
          `

            :

            `
          <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M3 3l18 18"/>
            <path d="M10.6 10.6a2 2 0 0 0 2.8 2.8"/>
            <path d="M9.9 4.2A10.9 10.9 0 0 1 12 4c6 0 9.5 6 9.5 6a17.7 17.7 0 0 1-3.1 3.7"/>
            <path d="M6.6 6.6C4.1 8.1 2.5 10 2.5 10S6 16 12 16c1.1 0 2.1-.2 3-.5"/>
          </svg>
          `;

}


function updateCodesVisibility() {

    const toggleButton =
        $("#toggleCodes");


    const toggleIcon =
        $("#toggleCodesIcon");


    const toggleText =
        $("#toggleCodesText");


    if (codesHidden) {

        setToggleCodesIcon(
            true
        );


        toggleText.textContent =
            "Show codes";


        toggleButton.title =
            "Show codes";


        toggleButton.setAttribute(
            "aria-label",
            "Show codes"
        );


        document

            .querySelectorAll(
                "[data-code]"
            )

            .forEach(

                element => {

                    element.textContent =
                        "••• •••";

                }

            );


        document

            .querySelectorAll(
                "[data-copy]"
            )

            .forEach(

                button => {

                    button.disabled =
                        true;

                }

            );

    }

    else {

        setToggleCodesIcon(
            false
        );


        toggleText.textContent =
            "Hide codes";


        toggleButton.title =
            "Hide codes";


        toggleButton.setAttribute(
            "aria-label",
            "Hide codes"
        );


        document

            .querySelectorAll(
                "[data-copy]"
            )

            .forEach(

                button => {

                    button.disabled =
                        false;

                }

            );


        refreshCodes();

    }

}


$("#toggleCodes").onclick =
    () => {

        codesHidden =
            !codesHidden;


        localStorage.setItem(
            "otpShelterCodesHidden",
            String(codesHidden)
        );

        updateCodesVisibility();

    };


/* ==========================================================
   OTP REFRESH
========================================================== */

async function refreshCodes() {


    if (
        refreshInProgress
    ) {
        return;
    }


    refreshInProgress =
        true;


    try {


        const visibleIds =

            new Set(

                [

                    ...document.querySelectorAll(
                        "[data-code]"
                    )

                ]

                    .map(

                        element =>
                            element.dataset.code

                    )

            );


        const visibleSites =

            sites.filter(

                site =>

                    visibleIds.has(
                        String(site.id)
                    )

            );


        await Promise.all(

            visibleSites.map(

                async site => {


                    try {


                        const data =

                            await request(

                                `/api/sites/${site.id}/otp`

                            );


                        const codeElement =

                            document.querySelector(

                                `[data-code="${site.id}"]`

                            );


                        const timerElement =

                            document.querySelector(

                                `[data-timer="${site.id}"]`

                            );


                        /* ==========================
                           CODE
                        =========================== */

                        if (codeElement) {


                            const newCode =

                                String(data.code)

                                    .replace(
                                        /(.{3})/g,
                                        "$1 "
                                    )

                                    .trim();


                            const oldCode =

                                codeElement.dataset.realCode ||
                                "";


                            /*
                             Save actual code.
                            */

                            codeElement.dataset.realCode =
                                newCode;


                            /*
                             Never show code
                             while hidden.
                            */

                            if (codesHidden) {

                                codeElement.textContent =
                                    "••• •••";

                            }

                            else {


                                /*
                                 Animate only
                                 when OTP changes.
                                */

                                if (

                                    oldCode

                                    &&

                                    oldCode !== newCode

                                ) {

                                    codeElement.classList.remove(
                                        "codeChanged"
                                    );


                                    void codeElement.offsetWidth;


                                    codeElement.classList.add(
                                        "codeChanged"
                                    );

                                }


                                codeElement.textContent =
                                    newCode;

                            }

                        }


                        /* ==========================
                           TIMER
                        =========================== */

                        if (timerElement) {

                            updateTimer(

                                timerElement,

                                data.seconds,

                                site.period || 30

                            );

                        }


                    } catch {

                        /*
                         Ignore individual
                         refresh failures.
                        */

                    }


                }

            )

        );


    } finally {

        refreshInProgress =
            false;

    }

}


/* ==========================================================
   TIMER
========================================================== */

function updateTimer(
    element,
    seconds,
    period = 30
) {

    const remaining =
        Number(seconds);


    const total =
        Number(period);


    const progress =

        Math.max(

            0,

            Math.min(

                1,

                remaining / total

            )

        );


    element.style.setProperty(

        "--progress",

        progress

    );


    let color =
        "var(--green)";


    if (

        progress <= .20

    ) {

        color =
            "var(--danger)";

    }

    else if (

        progress <= .45

    ) {

        color =
            "var(--yellow)";

    }

    else if (

        progress <= .70

    ) {

        color =
            "var(--blue)";

    }


    element.style.setProperty(

        "--timer-color",

        color

    );


    element.title =

        `${remaining} seconds remaining`;


    const label =

        element.querySelector(
            "span"
        );


    if (label) {

        label.textContent =
            remaining;

    }

}


/* ==========================================================
   COPY OTP
========================================================== */

async function copyCode(
    id
) {


    /*
     Security:
     Never copy while hidden.
    */

    if (codesHidden) {
        return;
    }


    const element =

        document.querySelector(

            `[data-code="${id}"]`

        );


    if (!element) {
        return;
    }


    const code =

        element.dataset.realCode

        ||

        element.textContent;


    const normalizedCode =

        code

            .replace(
                /\s/g,
                ""
            )

            .trim();


    if (

        !/^\d+$/.test(
            normalizedCode
        )

    ) {

        return;

    }


    try {

        await copyTextRobust(normalizedCode);

        showCopyFeedback(id);

    } catch {

        showToast(
            "Unable to copy code",
            "error"
        );

    }

}


/* ==========================================================
   ROBUST CLIPBOARD COPY
   Modern Clipboard API first, legacy fallback second.
========================================================== */

async function copyTextRobust(text) {

    // Prefer the modern API when available in the current context.
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
        try {
            await navigator.clipboard.writeText(text);
            return;
        } catch (error) {
            // Continue to the legacy fallback. This is expected on HTTP/LAN
            // origins or when browser clipboard permissions reject the request.
        }
    }

    const textarea = document.createElement("textarea");

    textarea.value = text;
    textarea.setAttribute("readonly", "");
    textarea.setAttribute("aria-hidden", "true");

    textarea.style.position = "fixed";
    textarea.style.top = "0";
    textarea.style.left = "0";
    textarea.style.width = "1px";
    textarea.style.height = "1px";
    textarea.style.padding = "0";
    textarea.style.border = "0";
    textarea.style.opacity = "0";
    textarea.style.pointerEvents = "none";

    document.body.appendChild(textarea);

    textarea.focus();
    textarea.select();
    textarea.setSelectionRange(0, textarea.value.length);

    let copied = false;

    try {
        copied = document.execCommand("copy");
    } finally {
        textarea.remove();
    }

    if (!copied) {
        throw new Error("Clipboard copy failed");
    }

}


/* ==========================================================
   COPY FEEDBACK
========================================================== */

function showCopyFeedback(
    id
) {

    const button =

        document.querySelector(

            `[data-copy="${id}"]`

        );


    if (!button) {
        return;
    }


    clearTimeout(
        button._copyTimer
    );


    if (

        !button.dataset.originalContent

    ) {

        button.dataset.originalContent =
            button.innerHTML;

    }


    button.innerHTML =
        "✓";


    button.title =
        "Copied";


    button.setAttribute(

        "aria-label",

        "Code copied"

    );


    button.style.color =
        "var(--green)";


    button._copyTimer =

        setTimeout(

            () => {


                button.innerHTML =

                    button.dataset.originalContent;


                button.title =
                    "Copy code";


                button.setAttribute(

                    "aria-label",

                    "Copy code"

                );


                button.style.color =
                    "";


            },

            1500

        );

}


/* ==========================================================
   MODAL
========================================================== */

function openAddModal() {


    const modal =
        $("#addModal");


    modal.classList.add(
        "open"
    );


    document.body.style.overflow =
        "hidden";


    setTimeout(

        () => {

            $("#input").focus();

        },

        50

    );

}


function closeAddModal() {


    const modal =
        $("#addModal");


    modal.classList.remove(
        "open"
    );


    document.body.style.overflow =
        "";

}


$("#toggleAdd").onclick =
    openAddModal;


$("#closeAddModal").onclick =
    closeAddModal;


$("#cancelAdd").onclick =
    closeAddModal;


$("#addModal").onclick =
    event => {


        if (

            event.target ===
            $("#addModal")

        ) {

            closeAddModal();

        }

    };


/* ==========================================================
   KEYBOARD
========================================================== */

document.addEventListener(

    "keydown",

    event => {


        /*
         ESC
        */

        if (

            event.key === "Escape"

        ) {


            $("#menuPanel")
                .classList.remove(
                    "open"
                );


            if (

                $("#addModal")
                    .classList.contains(
                        "open"
                    )

            ) {

                closeAddModal();

            }

        }


        /*
         CTRL + K
        */

        if (

            (

                event.ctrlKey ||
                event.metaKey

            )

            &&

            event.key.toLowerCase() ===
            "k"

        ) {

            event.preventDefault();

            $("#search").focus();

        }

    }

);


/* ==========================================================
   ADD ACCOUNT
========================================================== */

$("#addForm").onsubmit =
    async event => {


        event.preventDefault();


        const submitButton =
            $("#saveButton");


        try {


            submitButton.disabled =
                true;


            submitButton.textContent =
                "Saving...";


            await request(

                "/api/sites",

                {

                    method:
                        "POST",

                    headers: {

                        "Content-Type":
                            "application/json"

                    },

                    body:

                        JSON.stringify({

                            name:
                                $("#name").value,

                            input:
                                $("#input").value

                        })

                }

            );


            event.target.reset();


            closeAddModal();


            showToast(
                "Account added successfully"
            );


            await load();


        } catch (error) {


            showToast(

                error.message,

                "error"

            );


        } finally {


            submitButton.disabled =
                false;


            submitButton.textContent =
                "💾 Save account";

        }

    };


/* ==========================================================
   SEARCH
========================================================== */

$("#search").oninput =
    () => {


        render();


        refreshCodes();

    };


/* ==========================================================
   EDIT ACCOUNT NAME
========================================================== */

let editingSiteId = null;


function openEditModal(id) {

    const site = sites.find(
        item => String(item.id) === String(id)
    );

    if (!site) {
        return;
    }

    editingSiteId = id;

    $("#editName").value = site.name || "";
    $("#editModal").classList.add("open");

    document.body.style.overflow = "hidden";

    setTimeout(() => {
        $("#editName").focus();
        $("#editName").select();
    }, 50);

}


function closeEditModal() {

    $("#editModal").classList.remove("open");
    document.body.style.overflow = "";
    editingSiteId = null;

}


$("#closeEditModal").onclick = closeEditModal;
$("#cancelEdit").onclick = closeEditModal;


$("#editModal").onclick = event => {

    if (event.target === $("#editModal")) {
        closeEditModal();
    }

};


$("#editForm").onsubmit = async event => {

    event.preventDefault();

    const name = $("#editName").value.trim();

    if (!name) {
        showToast("Account name cannot be empty.", "error");
        return;
    }

    if (!editingSiteId) {
        return;
    }

    const button = $("#saveEditButton");
    const originalText = button.innerHTML;

    try {

        button.disabled = true;
        button.textContent = "Saving...";

        await request(
            `/api/sites/${editingSiteId}`,
            {
                method: "PATCH",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ name })
            }
        );

        closeEditModal();

        showToast("Account name updated");

        await load();

    } catch (error) {

        showToast(
            error.message || "Unable to update account.",
            "error"
        );

    } finally {

        button.disabled = false;
        button.innerHTML = originalText;

    }

};


/* ==========================================================
   DELETE
========================================================== */

async function removeSite(
    id
) {


    const site =

        sites.find(

            item =>

                String(item.id) ===
                String(id)

        );


    const name =

        site?.name ||
        "this account";


    if (

        !confirm(

            `Delete "${name}"?\n\nThis cannot be undone.`

        )

    ) {

        return;

    }


    try {


        await request(

            `/api/sites/${id}`,

            {

                method:
                    "DELETE"

            }

        );


        showToast(
            "Account deleted"
        );


        await load();


    } catch (error) {


        showToast(

            error.message,

            "error"

        );

    }

}


/* ==========================================================
   IMPORT
========================================================== */

$("#importFile").onchange =
    async event => {


        const file =
            event.target.files[0];


        if (!file) {
            return;
        }


        try {


            const data =

                JSON.parse(

                    await file.text()

                );


            if (data.format !== "otp-shelter" || data.version !== 2) {
                throw new Error("Only OTP-Shelter encrypted vault backups are supported.");
            }

            const result =

                await request(

                    "/api/import",

                    {

                        method:
                            "POST",

                        headers: {

                            "Content-Type":
                                "application/json"

                        },

                        body:
                            JSON.stringify({ vault: data })

                    }

                );


            showToast(

                `Imported ${result.imported} account(s)`

            );


            await load();


        } catch (error) {


            showToast(

                "Import failed: " +
                error.message,

                "error"

            );

        }


        event.target.value =
            "";

    };


/* ==========================================================
   CLICK OTP
========================================================== */

$("#sites").addEventListener(

    "click",

    event => {


        const codeElement =

            event.target.closest(
                "[data-code]"
            );


        if (!codeElement) {
            return;
        }


        copyCode(
            codeElement.dataset.code
        );

    }

);


/* ==========================================================
   KEYBOARD OTP
========================================================== */

$("#sites").addEventListener(

    "keydown",

    event => {


        if (

            event.key !== "Enter"

            &&

            event.key !== " "

        ) {

            return;

        }


        const codeElement =

            event.target.closest(
                "[data-code]"
            );


        if (!codeElement) {
            return;
        }


        event.preventDefault();


        copyCode(
            codeElement.dataset.code
        );

    }

);



function donateModal() {

    const addr = "thanksalot@walletofsatoshi.com"

    Swal.fire({
        title: "Send a Lightning tip ⚡",
        html: `
      <div style="margin-top:10px;font-size:16px;color:#888">
        If this tool is useful to you, consider a tip to support development and maintenance. Thank you! 🙏
        <br><br>
        Lightning Address ⚡
      </div>

      <img src="./donate_qrcode.png" style="margin:10px auto;display:block" />

      <div style="margin-top:4px;font-size:14px;font-family:monospace">
        ${addr}
      </div>
    `,
        confirmButtonText: "Copy Lightning address",
        confirmButtonColor: '#0fa90f',
    }).then((result) => {
        if (result.isConfirmed) {
            copyText(addr)
        }
    })
}



async function copyText(text) {

    try {

        if (navigator.clipboard && window.isSecureContext) {

            await navigator.clipboard.writeText(text)

        } else {

            const t = document.createElement("textarea")

            t.value = text

            document.body.appendChild(t)

            t.select()

            document.execCommand("copy")

            document.body.removeChild(t)

        }

        Swal.fire({
            toast: true,
            position: "top",
            icon: "success",
            title: "Text copied",
            showConfirmButton: false,
            timer: 1500
        })

    } catch (err) {

        Swal.fire({
            toast: true,
            position: "top",
            icon: "error",
            title: "Failed to copy",
            showConfirmButton: false,
            timer: 1500
        })

    }

}



/* ==========================================================
   PERIODIC REFRESH
========================================================== */

setInterval(

    () => { if (authenticated) refreshCodes(); },

    1000

);



/* ==========================================================
   START
========================================================== */

updateCodesVisibility();

checkStatus()
    .catch(error => {
        showToast(error.message, "error");
        setAuthenticatedUI(false);
    });

document.getElementById("donateBtn").addEventListener("click", donateModal);
