## 1) Get your Trello API Key

1. Log into Trello in your browser. 
2. Go to the **Power-Ups Admin Portal**:

   * `https://trello.com/power-ups/admin` 
3. Create a Power-Up (if you don’t already have one), then open it and go to the **API Key** tab.
4. If needed, click **Generate a new API key**. 

You’ll now have your **API key**.

References:
- [Logging in to Trello](../assets/Screenshot%202026-02-12%20at%202.58.50 PM.png)
- [Getting to the Power-Up Admin Portal](../assets/Screenshot%202026-02-12%20at%202.59.28 PM.png)
- [Creating a Power-Up](../assets/Screenshot%202026-02-12%20at%202.59.47 PM.png)
- [Generating an API key](../assets/Screenshot%202026-02-12%20at%203.00.24 PM.png)

---

## 2) Generate your Trello API Token

On that same **API key** page, there’s a **Token** link that takes you to the authorization flow to generate a token. 

You can also generate a token using the standard authorize URL format Trello documents (the docs show this pattern; your key gets inserted into the URL): 

* You approve access, then Trello shows you a **token**.
* Treat the token like a password (don’t share it). 

References:
- [Viewing your API Key and Credentials](../assets/Screenshot%202026-02-12%20at%203.00.24 PM.png)
- [Authorizing to generate a token](../assets/Screenshot%202026-02-12%20at%203.02.17 PM.png)

---

## 3) Set environment variables (recommended)

**WARNING: DO NOT COMMIT THESE CREDENTIALS TO GITHUB**
```bash
export TRELLO_KEY="your_api_key"
export TRELLO_TOKEN="your_api_token"
```

(If you’re on Windows PowerShell, you’d use `$env:TRELLO_KEY="..."`.)

---

## 4) Create a board + list for tickets

In Trello UI:

1. Create a board, e.g. **“Ironclad Vulnerability Remediation”**
2. Create lists:

   * **Backlog**
   * **In Progress**
   * **Remediated**

Your code will need the **List ID** of the destination list (usually Backlog).

---

## 5) Find the Board ID and List ID

### Quick UI method (works well for students)

* Open the board in a browser and add **`.json`** to the end of the board URL, then search the JSON for IDs.

  * Look for the board `"id"`
  * Look for list entries under `"lists"` and copy the list `"id"`

Once you have the destination list ID, set:

```bash
export TRELLO_LIST_ID="your_list_id"
```

References:
- [Viewing the JSON page](../assets/Screenshot%202026-02-12%20at%203.04.36 PM.png)

---

## 6) Sanity check: create a test card

Trello card creation uses:

* `POST https://api.trello.com/1/cards`
* Required params: `key`, `token`, `idList`, `name`, `desc` 

In your Python code, once `TRELLO_KEY`, `TRELLO_TOKEN`, and `TRELLO_LIST_ID` are set, you should be able to create a card and get back JSON describing the created card.
