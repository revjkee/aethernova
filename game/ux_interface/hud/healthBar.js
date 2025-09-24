/**
 * TeslaAI Genesis Industrial HUD System
 * Module: HealthBar
 * Version: v3.0-industrial
 * Authors: Consilium of 20 Agents & 3 Metagenerals
 * License: Internal Core Interactive UX Layer
 */

import * as THREE from 'three'
import { gsap } from 'gsap'

export class HealthBar {
  constructor(player, scene, camera) {
    this.player = player
    this.scene = scene
    this.camera = camera
    this.maxHealth = player.maxHealth
    this.currentHealth = player.health
    this.opacity = 1.0

    this._initHUD()
    this._animateHealthTransition()
  }

  _initHUD() {
    const geometry = new THREE.PlaneGeometry(1, 0.1)
    const material = new THREE.MeshBasicMaterial({
      color: 0x00ff00,
      transparent: true,
      opacity: this.opacity,
      depthTest: false
    })

    this.barMesh = new THREE.Mesh(geometry, material)
    this.barMesh.position.set(0, -0.95, -1.5)
    this.barMesh.scale.x = this.currentHealth / this.maxHealth

    // Add to HUD layer
    this.barMesh.renderOrder = 999
    this.scene.add(this.barMesh)
  }

  _animateHealthTransition() {
    // AI-friendly auto loop
    const animate = () => {
      const targetScale = this.player.health / this.maxHealth
      gsap.to(this.barMesh.scale, {
        x: targetScale,
        duration: 0.35,
        ease: 'power2.out',
        overwrite: true
      })

      this.barMesh.material.color.set(this._getColorByHealth(targetScale))
      requestAnimationFrame(animate)
    }

    animate()
  }

  _getColorByHealth(ratio) {
    if (ratio > 0.6) return 0x00ff00
    if (ratio > 0.3) return 0xffff00
    return 0xff0000
  }

  update() {
    // Optional runtime update hook for external forces
    const newHealth = this.player.health
    if (newHealth !== this.currentHealth) {
      this.currentHealth = newHealth
      this.barMesh.scale.x = newHealth / this.maxHealth
    }
  }

  fadeOut(delay = 1.5) {
    gsap.to(this.barMesh.material, {
      opacity: 0,
      delay,
      duration: 0.5,
      ease: 'power1.inOut'
    })
  }

  reset() {
    this.currentHealth = this.maxHealth
    this.barMesh.scale.x = 1
    this.barMesh.material.color.set(0x00ff00)
    this.barMesh.material.opacity = 1
  }

  destroy() {
    this.scene.remove(this.barMesh)
    this.barMesh.geometry.dispose()
    this.barMesh.material.dispose()
  }
}
