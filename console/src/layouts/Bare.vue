<script setup lang="ts">
// Centered card layout for unauthenticated flows (Materio's authentication-wrapper:
// the page colour behind one 400px card).
</script>

<template>
  <v-main>
    <v-container class="bare" fluid>
      <div class="bare__inner">
        <slot />
      </div>
    </v-container>
  </v-main>
</template>

<style scoped>
.bare {
  display: flex;
  min-height: 100dvh;
  align-items: center;
  justify-content: center;
  padding: 1.5rem;
}
.bare__inner {
  width: 100%;
  max-width: 400px;
  margin: auto;
}
</style>
