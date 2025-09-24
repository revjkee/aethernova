import { ethers } from 'ethers'
import { NEUROTokenABI } from '@/abi/NEUROToken'
import { getProvider, getSigner } from '@/shared/web3/web3Provider'
import { toast } from '@/shared/ui/toast'

// ENV-адрес смарт-контракта токена $NEURO
const CONTRACT_ADDRESS = import.meta.env.VITE_NEURO_TOKEN_ADDRESS as string

// Получение контракта с разным контекстом
export const getNEUROContract = (providerOrSigner?: ethers.Provider | ethers.Signer) => {
  const context = providerOrSigner ?? getProvider()
  return new ethers.Contract(CONTRACT_ADDRESS, NEUROTokenABI, context)
}

// Получение баланса токена
export const getTokenBalance = async (userAddress: string): Promise<string> => {
  try {
    const contract = getNEUROContract()
    const balance = await contract.balanceOf(userAddress)
    return ethers.formatEther(balance)
  } catch (err) {
    console.error('getTokenBalance error:', err)
    return '0'
  }
}

// Mint токенов (для админов/AI)
export const mintTokens = async (to: string, amount: string): Promise<void> => {
  try {
    const signer = getSigner()
    const contract = getNEUROContract(signer)
    const tx = await contract.mint(to, ethers.parseEther(amount))
    await tx.wait()
    toast.success(`Minted ${amount} $NEURO to ${to}`)
  } catch (err) {
    toast.error('Mint failed')
    console.error('mintTokens error:', err)
  }
}

// Transfer токенов
export const transferTokens = async (to: string, amount: string): Promise<void> => {
  try {
    const signer = getSigner()
    const contract = getNEUROContract(signer)
    const tx = await contract.transfer(to, ethers.parseEther(amount))
    await tx.wait()
    toast.success(`Transferred ${amount} $NEURO`)
  } catch (err) {
    toast.error('Transfer failed')
    console.error('transferTokens error:', err)
  }
}

// Поддержка permit (EIP-2612) — если контракт поддерживает
export const signPermit = async (owner: string, spender: string, value: string, deadline: number) => {
  try {
    const contract = getNEUROContract()
    const nonce = await contract.nonces(owner)
    const domain = {
      name: 'NEURO Token',
      version: '1',
      chainId: await contract.getChainId(),
      verifyingContract: CONTRACT_ADDRESS
    }

    const types = {
      Permit: [
        { name: 'owner', type: 'address' },
        { name: 'spender', type: 'address' },
        { name: 'value', type: 'uint256' },
        { name: 'nonce', type: 'uint256' },
        { name: 'deadline', type: 'uint256' }
      ]
    }

    const message = {
      owner,
      spender,
      value: ethers.parseUnits(value),
      nonce,
      deadline
    }

    const signer = getSigner()
    const signature = await signer.signTypedData(domain, types, message)
    return signature
  } catch (err) {
    console.error('signPermit error:', err)
    throw err
  }
}
