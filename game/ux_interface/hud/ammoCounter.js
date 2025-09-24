/**
 * TeslaAI Genesis UX HUD System
 * Module: AmmoCounter
 * Version: v3.0-industrial
 * Authors: Consilium of 20 Agents & 3 Metagenerals
 * License: Internal Core Interactive UX Layer
 */

import * as THREE from 'three'
import { Text } from 'troika-three-text'
import { gsap } from 'gsap'

export class AmmoCounter {
  constructor(player, scene, camera) {
    this.player = player
    this.scene = scene
    this.camera = camera

    this.textMesh = null
    this.previousAmmo = -1

    this._initAmmoText()
    this._bindUpdateLoop()
  }

  _initAmmoText() {
    this.textMesh = new Text()
    this.textMesh.text = `Ammo: ${this.player.ammo}`
    this.textMesh.fontSize = 0.08
    this.textMesh.position.set(0.6, -0.95, -1.5)
    this.textMesh.color = 0xffffff
    this.textMesh.anchorX = 'center'
    this.textMesh.anchorY = 'middle'
    this.textMesh.sync()

    this.textMesh.renderOrder = 1000
    this.textMesh.material.depthTest = false
    this.textMesh.material.transparent = true
    this.textMesh.material.opacity = 1.0

    this.scene.add(this.textMesh)
  }

  _bindUpdateLoop() {
    const animate = () => {
      if (this.player.ammo !== this.previousAmmo) {
        this._updateAmmoDisplay()
      }
      requestAnimationFrame(animate)
    }
    animate()
  }

  _updateAmmoDisplay() {
    const newAmmo = this.player.ammo
    this.previousAmmo = newAmmo

    gsap.to(this.textMesh.material, {
      opacity: 0.3,
      duration: 0.15,
      yoyo: true,
      repeat: 1,
      ease: 'power1.inOut'
    })

    this.textMesh.text = `Ammo: ${newAmmo}`
    this.textMesh.sync()
  }

  fadeOut(delay = 1.5) {
    gsap.to(this.textMesh.material, {
      opacity: 0,
      delay,
      duration: 0.5,
      ease: 'power1.inOut'
    })
  }

  reset() {
    this.previousAmmo = this.player.ammo
    this.textMesh.text = `Ammo: ${this.previousAmmo}`
    this.textMesh.material.opacity = 1.0
    this.textMesh.sync()
  }

  destroy() {
    this.scene.remove(this.textMesh)
    this.textMesh.geometry.dispose()
    this.textMesh.material.dispose()
  }
}
