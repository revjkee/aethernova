import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Textarea } from '@/components/ui/textarea'
import { toast } from '@/shared/hooks/useToast'
import { ClipboardCheck, KeyRound, Lock, RefreshCcw, UploadCloud } from 'lucide-react'
import { useGPGStore } from '@/store/privacy/gpgStore'
import { verifyGPGKey, generateGPGKey, importGPGKey, exportGPGKey, rotateGPGKey } from '@/shared/lib/crypto/gpg'
import { usePermission } from '@/shared/hooks/usePermission'
import { cn } from '@/shared/utils/classNames'

export const GPGKeyManager: React.FC = () => {
  const {
    publicKey,
    privateKey,
    fingerprint,
    status,
    lastRotated,
    setPublicKey,
    setPrivateKey,
    setFingerprint,
    setStatus,
    setLastRotated,
  } = useGPGStore()

  const [keyInput, setKeyInput] = useState('')
  const [generating, setGenerating] = useState(false)
  const [rotating, setRotating] = useState(false)
  const { hasPermission } = usePermission('crypto:write')

  useEffect(() => {
    if (publicKey && !fingerprint) {
      void verifyAndSetFingerprint()
    }
  }, [publicKey])

  const verifyAndSetFingerprint = async () => {
    try {
      const fp = await verifyGPGKey(publicKey)
      setFingerprint(fp)
      setStatus('verified')
      toast({ title: 'Ключ проверен', description: `Fingerprint: ${fp.slice(0, 12)}...` })
    } catch {
      setStatus('invalid')
      toast({ title: 'Ошибка верификации', description: 'Проверьте формат ключа', variant: 'destructive' })
    }
  }

  const handleGenerate = async () => {
    if (!hasPermission) return
    setGenerating(true)
    try {
      const { publicKey: pub, privateKey: priv, fingerprint: fp } = await generateGPGKey()
      setPublicKey(pub)
      setPrivateKey(priv)
      setFingerprint(fp)
      setStatus('verified')
      setLastRotated(new Date())
      toast({ title: 'Ключ сгенерирован', description: `Fingerprint: ${fp.slice(0, 12)}...` })
    } catch (e) {
      toast({ title: 'Ошибка генерации', description: (e as Error).message, variant: 'destructive' })
    } finally {
      setGenerating(false)
    }
  }

  const handleImport = async () => {
    try {
      await importGPGKey(keyInput)
      setPublicKey(keyInput)
      await verifyAndSetFingerprint()
    } catch (e) {
      toast({ title: 'Импорт не удался', description: (e as Error).message, variant: 'destructive' })
    }
  }

  const handleExport = async () => {
    try {
      const exported = await exportGPGKey(publicKey)
      await navigator.clipboard.writeText(exported)
      toast({ title: 'Ключ скопирован в буфер' })
    } catch {
      toast({ title: 'Ошибка экспорта', description: 'Не удалось скопировать ключ', variant: 'destructive' })
    }
  }

  const handleRotate = async () => {
    setRotating(true)
    try {
      const { publicKey: pub, privateKey: priv, fingerprint: fp } = await rotateGPGKey()
      setPublicKey(pub)
      setPrivateKey(priv)
      setFingerprint(fp)
      setStatus('verified')
      setLastRotated(new Date())
      toast({ title: 'Ключ ротации завершена', description: `Новый fingerprint: ${fp.slice(0, 12)}...` })
    } catch (e) {
      toast({ title: 'Ошибка ротации', description: (e as Error).message, variant: 'destructive' })
    } finally {
      setRotating(false)
    }
  }

  return (
    <motion.div
      className="space-y-6"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.4 }}
    >
      <Card className="border bg-muted/30">
        <CardHeader>
          <CardTitle>
            <KeyRound className="inline-block w-5 h-5 mr-2" />
            Управление GPG-ключами
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="space-y-2">
            <span className="text-muted-foreground">Импортировать ключ вручную</span>
            <Textarea
              placeholder="Вставьте ASCII-armored публичный ключ..."
              value={keyInput}
              onChange={(e) => setKeyInput(e.target.value)}
              className="text-xs font-mono"
              rows={6}
            />
            <Button onClick={handleImport} variant="secondary" size="sm" disabled={!keyInput}>
              <UploadCloud className="mr-1 w-4 h-4" /> Импорт
            </Button>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1">
              <span className="text-muted-foreground text-sm">Текущий fingerprint</span>
              <Input
                value={fingerprint || ''}
                readOnly
                className={cn('text-xs font-mono', status === 'invalid' && 'text-red-500')}
              />
            </div>
            <div className="flex gap-2">
              <Button onClick={handleExport} variant="outline" size="sm">
                <ClipboardCheck className="w-4 h-4 mr-1" />
                Копировать
              </Button>
              <Button onClick={handleGenerate} disabled={generating || !hasPermission} size="sm">
                <Lock className="w-4 h-4 mr-1" />
                Генерировать
              </Button>
              <Button
                onClick={handleRotate}
                disabled={rotating || !hasPermission}
                variant="ghost"
                size="sm"
              >
                <RefreshCcw className="w-4 h-4 mr-1" />
                Ротировать
              </Button>
            </div>
          </div>

          <div className="text-xs text-muted-foreground">
            Последняя ротация: {lastRotated?.toLocaleString() || 'никогда'}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  )
}

export default GPGKeyManager
