# Lunar API

## How to set up the Lunar API

> The API is used by your custom scripts to directly send requests to Lunar to buy/sell tokens

> The API is very basic, if high demand we will release a more advanced version that will support
> - Live editing from API
> - Task Creation from API
> - & more

### 1. Setup
- You can find code examples of the API in this repo
- Use this in your custom scripts

### 2. Task Creation
- You need to create a DeFi Extension task and turn it on for Lunar to receive your API requests

### 3. Available Functions

#### NewLunarClient(host, password)
- Creates a new API client instance
- Default host is "http://localhost:9192" if not specified

#### Login()
- Authenticates with the Lunar API using challenge-response
- Must be called before using other functions

#### GetTasks()
- Returns a list of available active tasks
- Requires prior authentication

#### BuyToken(taskUUID, tokenAddress, amount, poolAddress, isRaydium)
- Buys a token on Pump.Fun or Raydium
- Requires prior authentication
- Parameters:
  - taskUUID: The task identifier
  - tokenAddress: Address of the token to buy
  - amount: Amount to buy
  - poolAddress: Address of the liquidity pool
  - isRaydium: true for Raydium, false for Pump.Fun

#### SellToken(taskUUID, tokenAddress, percentage)
- Sells a previously bought token
- Requires prior authentication
- Parameters:
  - taskUUID: The task identifier
  - tokenAddress: Address of the token to sell
  - percentage: Percentage of holdings to sell (0-100)